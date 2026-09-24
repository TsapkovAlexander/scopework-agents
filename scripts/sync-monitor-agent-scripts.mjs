#!/usr/bin/env node
// Генерирует apps/web/src/lib/serverMonitoring/agentScripts.generated.ts из
// канонических файлов агента (единый источник правды — .sh-файлы):
//   apps/discovery-runner/discovery/monitor-push.sh
//   apps/discovery-runner/discovery/monitor-uninstall.sh
//   apps/web/src/lib/serverMonitoring/agent/install-manual-template.sh
// и то, чем бандл подписан: номер выпуска, ключи выпуска и подпись (константы ниже).
// Запуск: node scripts/sync-monitor-agent-scripts.mjs
// Выпуск и сумма бандла для подписи: node scripts/sync-monitor-agent-scripts.mjs --print-bundle
// Синхронизацию охраняет тест apps/web/src/lib/serverMonitoring/installerScript.test.ts.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const AGENT_SCRIPT_SOURCES = {
  MONITOR_PUSH_SH: "apps/discovery-runner/discovery/monitor-push.sh",
  MONITOR_UNINSTALL_SH: "apps/discovery-runner/discovery/monitor-uninstall.sh",
  BUILD_SNAPSHOT_JSON_PY: "apps/discovery-runner/discovery/build-snapshot-json.py",
  INSTALL_MANUAL_TEMPLATE_SH:
    "apps/web/src/lib/serverMonitoring/agent/install-manual-template.sh",
};

/**
 * Файлы, которые реально лежат на хосте в /opt/tracedocs/monitor и которые
 * самообновление подменяет. Шаблон инсталлера сюда не входит: он живёт на
 * платформе, и его правка не делает агент на сервере устаревшим.
 */
export const AGENT_BUNDLE_FILES = {
  "push.sh": "MONITOR_PUSH_SH",
  "build-snapshot-json.py": "BUILD_SNAPSHOT_JSON_PY",
  "uninstall.sh": "MONITOR_UNINSTALL_SH",
};

/**
 * Версия агента — отпечаток содержимого его файлов, а не число, которое надо
 * не забыть поднять. Забыть отпечаток невозможно: он меняется ровно тогда,
 * когда меняются файлы. Порядок ключей фиксирован сортировкой, разделитель —
 * \0, чтобы склейка «конец одного файла + начало другого» не давала ту же
 * строку при другом разбиении.
 */
export function monitorAgentVersion(files) {
  const canonical = Object.keys(files)
    .sort()
    .map((name) => `${name}\n${files[name]}`)
    .join("\0");
  return createHash("sha256").update(canonical, "utf8").digest("hex").slice(0, 12);
}

export const AGENT_SCRIPTS_TARGET =
  "apps/web/src/lib/serverMonitoring/agentScripts.generated.ts";

/** Номер выпуска агента мониторинга — тот же файл, что читает гейт версий. */
export const MONITOR_RELEASE_SOURCE = "apps/web/src/lib/serverMonitoring/agent/VERSION";
/**
 * Ключи выпуска — те же, что вшиваются в агента развёртывания (ADR-0082). В
 * образе web каталога apps/deploy-agent нет, поэтому ключи едут в сборку
 * сгенерированной константой.
 */
export const RELEASE_KEYS_DIR = "apps/deploy-agent/trust/release";
/** Подписи бандла, `<выпуск>.sig`; кладёт человек офлайн-ключом. */
export const BUNDLE_SIGNATURES_DIR = "apps/web/src/lib/serverMonitoring/agent/signatures";

const RELEASE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function readRepoFile(relPath) {
  return readFileSync(path.join(ROOT, relPath), "utf8");
}

/** Имена в каталоге; нет каталога — пусто: ни ключей, ни подписей. */
export function listRepoDir(relPath) {
  try {
    return readdirSync(path.join(ROOT, relPath));
  } catch (e) {
    if (e && e.code === "ENOENT") return [];
    throw e;
  }
}

/** Порядок байтов, как у `LC_ALL=C sort`: в нём же ключи стоят в push.sh. */
function byteOrder(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function readReleaseKeys(readFile, listDir) {
  return listDir(RELEASE_KEYS_DIR)
    .filter((name) => name.endsWith(".pub"))
    .sort(byteOrder)
    .map((name) => {
      const key = readFile(`${RELEASE_KEYS_DIR}/${name}`).trim();
      const raw = Buffer.from(key, "base64");
      // Ключ, который молча отбросили бы, превратил бы «подпись проверяется» в
      // «ни одна подпись не сходится» — отказ генерации громче.
      if (raw.length !== 32 || raw.toString("base64") !== key) {
        throw new Error(`${RELEASE_KEYS_DIR}/${name}: не std-base64 сырых 32 байт Ed25519`);
      }
      return key;
    });
}

/** Файлы бандла в том виде, в каком они лягут на хост. */
function readBundleFiles(readFile) {
  return Object.fromEntries(
    Object.entries(AGENT_BUNDLE_FILES).map(([fileName, constName]) => [
      fileName,
      readFile(AGENT_SCRIPT_SOURCES[constName]),
    ])
  );
}

/**
 * Номер выпуска. Он живёт в двух местах: в VERSION его читают changelog и гейт
 * версий, в push.sh — сам агент для пина. Разошедшиеся номера не собираются
 * вовсе — ни в модуль, ни в бандл для подписи.
 */
function readMonitorRelease(readFile, files) {
  const release = readFile(MONITOR_RELEASE_SOURCE).trim();
  if (!RELEASE.test(release)) {
    throw new Error(`${MONITOR_RELEASE_SOURCE}: «${release}» — не MAJOR.MINOR.PATCH`);
  }
  const declared = /^AGENT_RELEASE="([^"]*)"$/m.exec(files["push.sh"])?.[1];
  if (declared !== release) {
    throw new Error(
      `${AGENT_SCRIPT_SOURCES.MONITOR_PUSH_SH}: AGENT_RELEASE="${declared ?? ""}", а ${MONITOR_RELEASE_SOURCE} — ${release}`
    );
  }
  return release;
}

/**
 * Бандл, который отдаёт платформа, собранный из исходников: то, что подписывает
 * человек (`sign-agent-release.mjs sign-monitor`). Тело — тот же расчёт, что
 * `buildBundleBody` в agentBundle.ts; побайтовое совпадение держит
 * agentBundle.test.ts, а не память о том, что их две.
 */
export function buildMonitorBundle(readFile = readRepoFile) {
  const files = readBundleFiles(readFile);
  const release = readMonitorRelease(readFile, files);
  const sorted = Object.fromEntries(Object.keys(files).sort().map((name) => [name, files[name]]));
  const body = JSON.stringify({ version: monitorAgentVersion(files), release, files: sorted });
  return { release, body, sha256: createHash("sha256").update(body, "utf8").digest("hex") };
}

export function buildAgentScriptsModule(readFile = readRepoFile, listDir = listRepoDir) {
  const header =
    "// AUTO-GENERATED — не редактировать руками.\n" +
    "// Источник: scripts/sync-monitor-agent-scripts.mjs (и .sh-файлы, перечисленные в нём).\n" +
    "// Пересборка: node scripts/sync-monitor-agent-scripts.mjs\n\n";
  const body = Object.entries(AGENT_SCRIPT_SOURCES)
    .map(([name, rel]) => `export const ${name} = ${JSON.stringify(readFile(rel))};\n`)
    .join("\n");
  const bundle = readBundleFiles(readFile);
  const release = readMonitorRelease(readFile, bundle);
  const signatureFile = `${release}.sig`;
  const signature = listDir(BUNDLE_SIGNATURES_DIR).includes(signatureFile)
    ? readFile(`${BUNDLE_SIGNATURES_DIR}/${signatureFile}`).trim()
    : null;

  const version =
    `\n/** Отпечаток файлов агента: push.sh + build-snapshot-json.py + uninstall.sh. */\n` +
    `export const MONITOR_AGENT_VERSION = ${JSON.stringify(monitorAgentVersion(bundle))};\n`;
  const signing =
    `\n/** Выпуск агента (${MONITOR_RELEASE_SOURCE}): едет в бандле и в подписываемом сообщении. */\n` +
    `export const MONITOR_AGENT_BUNDLE_RELEASE = ${JSON.stringify(release)};\n` +
    `\n/** Ключи выпуска (${RELEASE_KEYS_DIR}/*.pub): std-base64 сырых 32 байт Ed25519. */\n` +
    `export const MONITOR_AGENT_RELEASE_KEYS: readonly string[] = ${JSON.stringify(readReleaseKeys(readFile, listDir))};\n` +
    `\n/** Подпись бандла (${BUNDLE_SIGNATURES_DIR}/<выпуск>.sig); null — выпуск не подписан. */\n` +
    `export const MONITOR_AGENT_BUNDLE_SIGNATURE: string | null = ${JSON.stringify(signature)};\n`;
  return header + body + version + signing;
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain && process.argv.includes("--print-bundle")) {
  // Что именно подписывается: выпуск и сумма бандла, который отдаст платформа.
  const { release, sha256 } = buildMonitorBundle();
  console.log(`release=${release}\nsha256=${sha256}`);
} else if (isMain) {
  writeFileSync(path.join(ROOT, AGENT_SCRIPTS_TARGET), buildAgentScriptsModule());
  console.log(`written ${AGENT_SCRIPTS_TARGET}`);
}
