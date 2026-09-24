#!/usr/bin/env node
/**
 * Подпись выпуска агента ключом, которого нет ни у платформы, ни в базе
 * (ADR-0082, задачи С1.2–С1.4), и проверка подписанного выпуска.
 *
 * ЗАЧЕМ ЭТО ДЕЛАЕТ ЧЕЛОВЕК, А НЕ СБОРКА. Приватный ключ лежит у владельца
 * платформы на его машине. Ключ, доступный CI или web, не защищает от их
 * взлома — а именно это и есть главный сценарий: тот, кто завладел платформой,
 * получает произвольный код на каждом подключённом сервере клиента.
 *
 * ЧТО ПОДПИСЫВАЕТСЯ. Сообщение собирается ровно так же, как в агенте
 * (`ReleaseBinaryMessage` в internal/agent/release_trust.go):
 *
 *     agent-binary\n<версия>\n<sha256 в нижнем регистре>\n<архитектура>
 *
 * Версия входит в подпись не для красоты: без неё подпись старого бинаря
 * годилась бы для отката, а откат — способ снять уже поставленную защиту.
 *
 * ПОРЯДОК:
 *
 *   1. Один раз завести ключ:
 *        node scripts/deploy/sign-agent-release.mjs keygen ~/.scopework/agent-release.key
 *      Скрипт напечатает ПУБЛИЧНЫЙ ключ — он ложится файлом в
 *      apps/deploy-agent/trust/release/<имя>.pub, сборка вшивает его в агента
 *      (scripts/build-deploy-agent.sh), отпечаток публикуется на сайте.
 *
 *   2. На каждый выпуск, для каждой архитектуры:
 *        node scripts/deploy/sign-agent-release.mjs sign ~/.scopework/agent-release.key \
 *          <файл бинаря> <версия> <arch>
 *      Рядом с бинарём появится `<файл>.sig` — его и раздаёт платформа
 *      заголовком `X-Release-Signature`.
 *
 *   3. Перед выкладкой:
 *        node scripts/deploy/sign-agent-release.mjs verify <каталог выпуска>
 *      Каждый бинарь выпуска обязан быть подписан одним из ключей
 *      apps/deploy-agent/trust/release для своей версии и архитектуры — ровно
 *      то, что проверит агент перед подменой своего файла. Выпуск, который
 *      агент отверг бы, обнаруживается здесь, а не на серверах клиентов.
 *
 * БАНДЛ АГЕНТА МОНИТОРИНГА (ADR-0095, п. 10) подписывается тем же ключом:
 *
 *        node scripts/deploy/sign-agent-release.mjs sign-monitor ~/.scopework/agent-release.key
 *        node scripts/deploy/sign-agent-release.mjs verify-monitor
 *
 *   Сообщение — `monitor-bundle\n<выпуск>\n<sha256 бандла>`, выпуск и сумма —
 *   из `scripts/sync-monitor-agent-scripts.mjs` (тот же бандл, что отдаёт
 *   платформа). Подпись ложится в репозиторий,
 *   apps/web/src/lib/serverMonitoring/agent/signatures/<выпуск>.sig: бандл
 *   детерминирован, и платформа отдаёт её вместе с ним. Порядок —
 *   docs/runbooks/agent-release.md, «Подпись бандла агента мониторинга».
 *
 * ПРИВАТНЫЙ КЛЮЧ НИКОГДА НЕ ПОПАДАЕТ В РЕПОЗИТОРИЙ И НА СЕРВЕР. Скрипт его
 * только читает с указанного пути и ничего никуда не отправляет.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildMonitorBundle } from "../sync-monitor-agent-scripts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/** Открытые ключи выпуска, которые вшиваются в агента. */
export const RELEASE_KEYS_DIR = path.join(ROOT, "apps/deploy-agent/trust/release");

/** Подписи бандла агента мониторинга: `<выпуск>.sig`, платформа берёт их при сборке. */
export const MONITOR_SIGNATURES_DIR = path.join(ROOT, "apps/web/src/lib/serverMonitoring/agent/signatures");

const ARCHES = ["amd64", "arm64"];
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function releaseBinaryMessage(version, sha256Hex, arch) {
  return Buffer.from(`agent-binary\n${version}\n${sha256Hex.toLowerCase()}\n${arch}`, "utf8");
}

/**
 * Сообщение подписи бандла — так его собирают агент (`verify_bundle_signature`
 * в monitor-push.sh) и платформа (`verifiedBundleSignature` в agentBundle.ts).
 * Выпуск внутри по той же причине, что у бинаря: без него подпись старого
 * бандла годилась бы для отката.
 */
export function monitorBundleMessage(release, sha256Hex) {
  return Buffer.from(`monitor-bundle\n${release}\n${sha256Hex}`, "utf8");
}

const fileSha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

/**
 * Ключи `<каталог>/*.pub` в порядке имён — тот же набор, что вшивает сборка.
 *
 * Битый файл — исключение, а не пропуск: проверка без одного из ключей
 * отвергла бы законную подпись и выглядела бы как «подпись не та».
 */
export function readTrustedKeys(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".pub"))
    .sort()
    .map((name) => {
      const text = readFileSync(path.join(dir, name), "utf8").replace(/\r?\n$/, "");
      const raw = Buffer.from(text, "base64");
      if (text.includes("\n") || raw.length !== 32 || raw.toString("base64") !== text) {
        throw new Error(`${name}: не std-base64 открытого ключа Ed25519 (32 байта)`);
      }
      const key = createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
        format: "jwk",
      });
      return { name, key };
    });
}

export function signReleaseBinary(keyPath, binaryPath, version, arch) {
  const sha = fileSha256(binaryPath);
  const key = createPrivateKey(readFileSync(keyPath, "utf8"));
  const signature = sign(null, releaseBinaryMessage(version, sha, arch), key).toString("base64");
  writeFileSync(`${binaryPath}.sig`, `${signature}\n`, { mode: 0o644 });
  return sha;
}

/** Подпись бандла `{ release, sha256 }` в `<каталог>/<выпуск>.sig`; путь к файлу. */
export function signMonitorBundle(keyPath, bundle, signaturesDir) {
  if (!SEMVER.test(bundle.release)) {
    throw new Error(`выпуск должен быть MAJOR.MINOR.PATCH, получено «${bundle.release}»`);
  }
  if (!/^[0-9a-f]{64}$/.test(bundle.sha256)) {
    throw new Error(`sha256 бандла — 64 hex в нижнем регистре, получено «${bundle.sha256}»`);
  }
  const key = createPrivateKey(readFileSync(keyPath, "utf8"));
  const signature = sign(null, monitorBundleMessage(bundle.release, bundle.sha256), key).toString("base64");
  mkdirSync(signaturesDir, { recursive: true });
  const file = path.join(signaturesDir, `${bundle.release}.sig`);
  writeFileSync(file, `${signature}\n`, { mode: 0o644 });
  return file;
}

/**
 * Подпись бандла сходится с одним из ключей — ровно то, что проверит агент с
 * вшитыми ключами перед подменой своих файлов. Отказ здесь — это отказ
 * самообновления на каждом сервере, увиденный до выката.
 */
export function verifyMonitorBundle(bundle, signaturesDir, keys) {
  const problems = [];
  const lines = [];
  const name = `${bundle.release}.sig`;

  if (keys.length === 0) {
    problems.push(
      "в apps/deploy-agent/trust/release нет ключей — проверка не проведена: ключей нет.\n" +
        "    Без ключей агент мониторинга подпись не проверяет и ставит бандл как раньше"
    );
    return { ok: false, problems, lines };
  }
  const file = path.join(signaturesDir, name);
  if (!existsSync(file)) {
    problems.push(`нет подписи ${name} — агент с ключами бандл ${bundle.release} не поставит`);
    return { ok: false, problems, lines };
  }
  const signature = Buffer.from(readFileSync(file, "utf8").trim(), "base64");
  if (signature.length !== 64) {
    problems.push(`подпись ${name} испорчена: это не 64 байта base64`);
    return { ok: false, problems, lines };
  }
  const message = monitorBundleMessage(bundle.release, bundle.sha256);
  const signer = keys.find(({ key }) => verify(null, message, key, signature));
  if (!signer) {
    problems.push(
      `подпись ${name} не проходит ни одним ключом trust/release для бандла ${bundle.release} (sha256 ${bundle.sha256}) —\n` +
        "    чужой ключ, подпись другого выпуска или скрипты правили после подписи"
    );
    return { ok: false, problems, lines };
  }
  lines.push(`${bundle.release}: ${bundle.sha256} — подпись ключом ${signer.name}`);
  return { ok: true, problems, lines };
}

/**
 * Каждый бинарь выпуска подписан доверенным ключом для своей версии и
 * архитектуры. Версия — имя каталога выпуска: так его раскладывает сборка и так
 * его читает платформа.
 */
export function verifyRelease(releaseDir, keys) {
  const problems = [];
  const lines = [];
  const version = path.basename(path.resolve(releaseDir));

  if (keys.length === 0) {
    problems.push(
      "в apps/deploy-agent/trust/release нет ключей — проверять нечем, проверка не проведена.\n" +
        "    Выпуск без ключей неподписанный: агенты его ставят, не проверяя подпись"
    );
    return { ok: false, problems, lines };
  }
  if (!SEMVER.test(version)) {
    problems.push(`каталог выпуска «${version}» — не версия MAJOR.MINOR.PATCH`);
    return { ok: false, problems, lines };
  }

  for (const arch of ARCHES) {
    const binary = path.join(releaseDir, `deploy-agent-linux-${arch}`);
    if (!existsSync(binary)) {
      problems.push(`нет бинаря deploy-agent-linux-${arch}`);
      continue;
    }
    if (!existsSync(`${binary}.sig`)) {
      problems.push(`нет подписи deploy-agent-linux-${arch}.sig — агент с ключом этот бинарь (${arch}) не поставит`);
      continue;
    }
    const signature = Buffer.from(readFileSync(`${binary}.sig`, "utf8").trim(), "base64");
    if (signature.length !== 64) {
      problems.push(`подпись deploy-agent-linux-${arch}.sig испорчена: это не 64 байта base64`);
      continue;
    }
    const sha = fileSha256(binary);
    const message = releaseBinaryMessage(version, sha, arch);
    const signer = keys.find(({ key }) => verify(null, message, key, signature));
    if (!signer) {
      problems.push(
        `подпись deploy-agent-linux-${arch} не проходит ни одним ключом trust/release для версии ${version} —\n` +
          "    чужой ключ, другая версия или другая архитектура"
      );
      continue;
    }
    lines.push(`${arch}: ${sha} — подпись ключом ${signer.name}`);
  }
  return { ok: problems.length === 0, problems, lines };
}

function fail(message) {
  console.error(message);
  process.exit(2);
}

function main(command, rest) {
  if (command === "keygen") {
    const [out] = rest;
    if (!out) fail("укажите путь, куда положить приватный ключ");
    // Не перезаписываем никогда: публичная часть уже может быть вшита в агентов,
    // и второй keygen по тому же пути оставил бы выпуски без подписи.
    if (existsSync(out)) fail(`файл ${out} уже существует — ключ не перезаписывается`);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(out, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
    chmodSync(out, 0o600);
    const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
    console.log("Приватный ключ записан:", out, "(права 600, в репозиторий не кладём)");
    console.log("Публичный ключ для сборки агента:");
    console.log(raw.toString("base64"));
    return;
  }

  if (command === "sign") {
    const [keyPath, binaryPath, version, arch] = rest;
    if (!keyPath || !binaryPath || !version || !arch) {
      fail("порядок: sign <ключ> <бинарь> <версия> <arch>");
    }
    if (!SEMVER.test(version)) {
      fail(`версия должна быть MAJOR.MINOR.PATCH, получено «${version}»`);
    }
    const sha = signReleaseBinary(keyPath, binaryPath, version, arch);
    console.log("sha256:", sha);
    console.log("подпись записана:", `${binaryPath}.sig`);
    return;
  }

  if (command === "verify") {
    const [releaseDir] = rest;
    if (!releaseDir) fail("порядок: verify <каталог выпуска>");
    let keys;
    try {
      keys = readTrustedKeys(RELEASE_KEYS_DIR);
    } catch (e) {
      console.error(`ОТКАЗ: ключи trust/release не читаются: ${e instanceof Error ? e.message : e}`);
      process.exit(1);
    }
    const result = verifyRelease(releaseDir, keys);
    if (!result.ok) {
      console.error(`ОТКАЗ: выпуск ${releaseDir}\n`);
      for (const line of result.problems) console.error(`  ${line}`);
      process.exit(1);
    }
    for (const line of result.lines) console.log(line);
    console.log(`OK: выпуск ${path.basename(path.resolve(releaseDir))} подписан доверенным ключом`);
    return;
  }

  if (command === "sign-monitor") {
    const [keyPath] = rest;
    if (!keyPath) fail("порядок: sign-monitor <ключ>");
    const bundle = buildMonitorBundle();
    const file = signMonitorBundle(keyPath, bundle, MONITOR_SIGNATURES_DIR);
    console.log("выпуск:", bundle.release);
    console.log("sha256:", bundle.sha256);
    console.log("подпись записана:", path.relative(ROOT, file));
    console.log("дальше: node scripts/sync-monitor-agent-scripts.mjs && node scripts/deploy/sign-agent-release.mjs verify-monitor");
    return;
  }

  if (command === "verify-monitor") {
    let keys;
    try {
      keys = readTrustedKeys(RELEASE_KEYS_DIR);
    } catch (e) {
      console.error(`ОТКАЗ: ключи trust/release не читаются: ${e instanceof Error ? e.message : e}`);
      process.exit(1);
    }
    const bundle = buildMonitorBundle();
    const result = verifyMonitorBundle(bundle, MONITOR_SIGNATURES_DIR, keys);
    if (!result.ok) {
      console.error(`ОТКАЗ: бандл агента мониторинга ${bundle.release}\n`);
      for (const line of result.problems) console.error(`  ${line}`);
      process.exit(1);
    }
    for (const line of result.lines) console.log(line);
    console.log(`OK: бандл агента мониторинга ${bundle.release} подписан доверенным ключом`);
    return;
  }

  fail(
    "команды: keygen <путь> | sign <ключ> <бинарь> <версия> <arch> | verify <каталог выпуска>\n" +
      "         | sign-monitor <ключ> | verify-monitor"
  );
}

const isMain =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const [, , command, ...rest] = process.argv;
  main(command, rest);
}
