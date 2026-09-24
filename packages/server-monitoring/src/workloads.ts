import { z } from "zod";
import { containerEventSchema } from "./schema.js";

/**
 * Секция `workloads` такта агента развёртывания (ADR-0091).
 *
 * Эта схема — точка правды контракта: Go-тип агента, RPC
 * `deploy_report_workloads` и приём в ручке такта повторяют её и сверяются по
 * золотой фикстуре `fixtures/workloads-section.json`.
 *
 * КАЖДЫЙ КЛЮЧ ОБЯЗАТЕЛЕН, «нет данных» — null (с причиной рядом, ADR-0066
 * решение 5). Go-тип маршалится без omitempty, и сравнение с фикстурой
 * однозначно: отсутствие ключа и null не значат двух разных вещей.
 *
 * Незнакомые ключи внутри v1 отбрасываются, а не отвергают секцию: новый агент
 * на старой платформе иначе терял бы доставку целиком. Несовместимая форма —
 * другая версия, и её отвергают целиком (решение 1).
 */

export const WORKLOADS_SECTION_VERSION = 1 as const;
export const WORKLOADS_MAX_CONTAINERS = 100;
export const WORKLOADS_MAX_VOLUMES = 50;
export const WORKLOADS_MAX_PEERS = 32;
export const WORKLOADS_MAX_EVENTS = 20;
export const WORKLOADS_MAX_BUCKETS = 12;
export const WORKLOADS_BUCKET_SECONDS = 300;
export const WORKLOADS_MAX_SECTION_BYTES = 256 * 1024;
/**
 * Бюджет всего тела такта у агента: на 32 КиБ ниже потолка 768 КиБ, потому
 * что 413 роняет такт вместе с желаемым состоянием (решение 9). Секция
 * получает min(256 КиБ, этот бюджет − остальное тело).
 */
export const WORKLOADS_MAX_TICK_BODY_BYTES = 736 * 1024;

/**
 * План — 5 выборок по 60 с на корзину (решение 2), остальное — запас на сдвиг
 * таймера.
 */
const MAX_BUCKET_SAMPLES = 10;

const containerId = z.string().regex(/^[0-9a-f]{64}$/);
const imageId = z.string().regex(/^sha256:[0-9a-f]{64}$/);

/**
 * Код причины — строка, а не enum: новая причина у агента не должна отвергать
 * всю секцию на старой платформе.
 */
const reasonCode = z.string().regex(/^[a-z0-9_]{1,64}$/);

/**
 * Только UTC с `Z`: выравнивание корзины и ключ ряда в базе не должны зависеть
 * от пояса, в котором агент записал момент.
 */
const timestamp = z.string().datetime();

/**
 * Выше 2^53 − 1 JSON.parse молча округляет, и в bigint базы легло бы не то,
 * что прислал агент. Такое число отвергается, агент держит счётчики в пределе.
 */
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const metric = count.nullable();

const signalStatus = z.enum(["ok", "unavailable"]);
const composeLabel = z.string().min(1).max(128).nullable();

function parseIPv4(text: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  return octets.every((o) => o <= 255) ? octets : null;
}

function parseIPv6(text: string): number[] | null {
  let rest = text.toLowerCase();
  let v4: number[] | null = null;
  if (rest.includes(".")) {
    const at = rest.lastIndexOf(":");
    v4 = parseIPv4(rest.slice(at + 1));
    if (!v4) return null;
    rest = `${rest.slice(0, at + 1)}0:0`;
  }
  const halves = rest.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string) => (part === "" ? [] : part.split(":"));
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...Array<string>(missing).fill("0"), ...tail];
  if (!all.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  const bytes = all.flatMap((g) => {
    const n = parseInt(g, 16);
    return [n >> 8, n & 0xff];
  });
  if (v4) bytes.splice(12, 4, ...v4);
  return bytes;
}

function isInternalIPv4([a, b, c, d]: number[]): boolean {
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 224 && b === 0 && c === 0) ||
    (a === 0 && b === 0 && c === 0 && d === 0)
  );
}

/**
 * Набор `isInternalIP` агента (`internal/agent/threat.go`: loopback, private,
 * link-local, unspecified, link-local multicast) плюс 100.64/10 — решение 4.
 * Не уже набора агента: адрес, который агент считает внутренним, иначе
 * отвергал бы всю секцию.
 */
function isInternalAddress(text: string): boolean {
  const v4 = parseIPv4(text);
  if (v4) return isInternalIPv4(v4);
  const v6 = text.includes(":") ? parseIPv6(text) : null;
  if (!v6) return false;
  const zeroPrefix = (n: number) => v6.slice(0, n).every((b) => b === 0);
  if (zeroPrefix(10) && v6[10] === 0xff && v6[11] === 0xff) return isInternalIPv4(v6.slice(12));
  if (zeroPrefix(15) && (v6[15] === 0 || v6[15] === 1)) return true;
  return (
    (v6[0] & 0xfe) === 0xfc ||
    (v6[0] === 0xfe && (v6[1] & 0xc0) === 0x80) ||
    (v6[0] === 0xff && (v6[1] & 0x0f) === 0x02)
  );
}

/**
 * Повтор ключа в одном наборе база молча схлопнула бы (ON CONFLICT DO NOTHING
 * по ряду, замена набора текущих значений) — и потеряла бы строку. Docker
 * повторов имён не допускает, так что повтор — ошибка агента.
 */
function unique<K extends string>(key: K) {
  return (items: Record<K, string>[], ctx: z.RefinementCtx) => {
    const seen = new Set<string>();
    items.forEach((item, i) => {
      if (seen.has(item[key])) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [i, key], message: `duplicate ${key}` });
      }
      seen.add(item[key]);
    });
  };
}

const imageSchema = z.object({
  ref: z.string().min(1).max(512).nullable(),
  id: imageId.nullable(),
  verdict: z.enum(["match", "mismatch", "unknown"]),
  reason: reasonCode.nullable(),
  baseline_id: imageId.nullable(),
  /**
   * `adopted` снят у стека, который уже работал до агента: фиксирует, что
   * стояло, и не доказывает, что образ был чистым (решение 6).
   */
  baseline_source: z.enum(["apply", "adopted"]).nullable(),
});

const cgroupSchema = z.object({
  status: signalStatus,
  reason: reasonCode.nullable(),
  memory_bytes: metric,
  /** При status ok null значит предел «max». */
  memory_max_bytes: metric,
  oom_kills: metric,
  cpu_usage_usec: metric,
  cpu_nr_throttled: metric,
  pids: metric,
});

const peerSchema = z.object({
  address: z.string().max(45).refine(isInternalAddress, "peer address must be internal (ADR-0091, decision 4)"),
  /**
   * Порт службы: свой LISTEN-порт у входящего, порт пира у исходящего.
   * Эфемерный порт в ключ не идёт — иначе каждое соединение стало бы отдельным
   * пиром, и count потерял бы смысл.
   */
  port: z.number().int().min(0).max(65535),
  direction: z.enum(["in", "out"]),
  count: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
});

const networkSchema = z.object({
  status: signalStatus,
  reason: reasonCode.nullable(),
  /** Общий netns приписан владельцу (решение 3): у соседа — shared_netns и id владельца. */
  netns_owner: containerId.nullable(),
  established: metric,
  inbound: metric,
  outbound: metric,
  /** Публичные пиры — только суммой: адрес посетителя приложения клиента с хоста не уезжает (решение 4). */
  external: metric,
  peers: z.array(peerSchema).max(WORKLOADS_MAX_PEERS),
  peers_truncated: z.boolean(),
});

const containerSchema = z.object({
  id: containerId,
  name: z.string().min(1).max(256),
  compose_project: composeLabel,
  compose_service: composeLabel,
  /** compose-проект = slug приложения платформы; при отсечении такие уходят последними (решение 9). */
  platform_stack: z.boolean(),
  state: z.string().min(1).max(32),
  health: z.string().min(1).max(32).nullable(),
  restart_count: count,
  /** null, пока контейнер не завершён: Docker держит там 0, и это читалось бы как чистый выход. */
  exit_code: z.number().int().min(-2147483648).max(2147483647).nullable(),
  oom_killed: z.boolean().nullable(),
  /** Нулевое время Docker (0001-01-01) и здесь, и в finished_at — null. */
  started_at: timestamp.nullable(),
  finished_at: timestamp.nullable(),
  image: imageSchema,
  cgroup: cgroupSchema,
  network: networkSchema,
});

const volumeSchema = z.object({
  name: z.string().min(1).max(256),
  driver: z.string().min(1).max(128),
  compose_project: composeLabel,
  platform_stack: z.boolean(),
  status: signalStatus,
  reason: reasonCode.nullable(),
  /** Заполненность ФС, на которой лежит том, а не размер тома (решение 3). */
  fs_total_bytes: metric,
  fs_avail_bytes: metric,
  /**
   * total − avail, где avail — блоки, доступные непривилегированному процессу
   * (Bavail), а не df-овское total − Bfree; так же считает диски хоста агент
   * (`internal/agent/hostmetrics.go`, `statfsUsage`). Вопрос здесь — кончится
   * ли место у состояния, а блоки, зарезервированные под root, приложению не
   * достанутся.
   */
  fs_used_bytes: metric,
});

/**
 * Строка корзины. Ключ ряда — имя, а не id: имя переживает пересоздание, id —
 * нет. Счётчики cgroup и перезапуски — дельта за корзину с учётом сброса и
 * смены id (решение 2).
 */
const bucketContainerSchema = z.object({
  name: z.string().min(1).max(256),
  mem_avg_bytes: metric,
  mem_max_bytes: metric,
  cpu_usage_usec: metric,
  cpu_nr_throttled: metric,
  oom_kills: metric,
  pids_max: metric,
  conns_max: metric,
  restarts: metric,
});

const bucketVolumeSchema = z.object({
  name: z.string().min(1).max(256),
  used_avg_bytes: metric,
  used_max_bytes: metric,
  total_bytes: metric,
});

const bucketSchema = z.object({
  start: timestamp.refine(
    (s) => Date.parse(s) % (WORKLOADS_BUCKET_SECONDS * 1000) === 0,
    `bucket start must be aligned to ${WORKLOADS_BUCKET_SECONDS} s since the UTC epoch`
  ),
  seconds: z.literal(WORKLOADS_BUCKET_SECONDS),
  /**
   * Только плановые выборки раз в 60 с. Внеочередные, разбуженные потоком
   * docker events (решение 5), обновляют события и текущие значения, но в
   * корзину не идут: контейнер в цикле перезапуска будил бы их каждые 10 с,
   * раздувал бы samples за предел и перекашивал бы avg к моментам падений.
   */
  samples: z.number().int().min(1).max(MAX_BUCKET_SAMPLES),
  truncated: z.boolean(),
  containers: z.array(bucketContainerSchema).max(WORKLOADS_MAX_CONTAINERS).superRefine(unique("name")),
  volumes: z.array(bucketVolumeSchema).max(WORKLOADS_MAX_VOLUMES).superRefine(unique("name")),
});

/**
 * События — ровно поля ADR-0061, но каждый ключ обязателен, как во всей
 * секции. Хвост лога отвергается явно, а не отбрасывается молча: агент
 * развёртывания его не шлёт (решение 5), и пришедший хвост — нарушение
 * контракта, которое должно быть видно, а не данные.
 */
const workloadEventSchema = containerEventSchema
  .omit({ log_tail: true })
  .required()
  .extend({
    log_tail: z.never({ message: "deploy agent sends no log tails (ADR-0091, decision 5)" }).optional(),
  });

export const workloadsSectionSchema = z
  .object({
    version: z.literal(WORKLOADS_SECTION_VERSION),
    /** Старт рядов процесса агента: по нему платформа видит разрыв после перезапуска (решение 2). */
    since: timestamp,
    collected_at: timestamp,
    truncated: z.boolean(),
    omitted_containers: count,
    omitted_volumes: count,
    /**
     * Оба счётчика накопительные с `since` (старт процесса агента), и
     * подтверждение такта их не обнуляет: ответ такта может потеряться, и то же
     * число пришло бы повторно как новая потеря. Монотонный счётчик
     * идемпотентен — потери платформа видит разницей между тактами одного `since`.
     */
    dropped_buckets: count,
    dropped_events: count,
    containers: z.array(containerSchema).max(WORKLOADS_MAX_CONTAINERS).superRefine(unique("name")),
    volumes: z.array(volumeSchema).max(WORKLOADS_MAX_VOLUMES).superRefine(unique("name")),
    buckets: z.array(bucketSchema).max(WORKLOADS_MAX_BUCKETS).superRefine(unique("start")),
    events: z.array(workloadEventSchema).max(WORKLOADS_MAX_EVENTS),
  })
  .superRefine((section, ctx) => {
    // Корзина пишется один раз (ON CONFLICT DO NOTHING, решение 7): незакрытая
    // заняла бы ключ неполной строкой, и полная при следующей доставке уже не легла бы.
    const collectedAt = Date.parse(section.collected_at);
    section.buckets.forEach((bucket, i) => {
      const end = Date.parse(bucket.start) + bucket.seconds * 1000;
      if (Number.isFinite(collectedAt) && Number.isFinite(end) && end > collectedAt) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["buckets", i, "start"],
          message: "bucket is not closed at collected_at",
        });
      }
    });
  });

export type WorkloadsSection = z.infer<typeof workloadsSectionSchema>;
export type WorkloadContainer = WorkloadsSection["containers"][number];
export type WorkloadVolume = WorkloadsSection["volumes"][number];
export type WorkloadBucket = WorkloadsSection["buckets"][number];
export type WorkloadEvent = WorkloadsSection["events"][number];

export type WorkloadsParseResult = { ok: true; section: WorkloadsSection } | { ok: false; reason: string };

const utf8 = new TextEncoder();

/**
 * Разбор секции с пределами решения 9. Отказ — целиком: агент увидит
 * `accepted.workloads = -1` и сохранит очередь (решение 1).
 *
 * Размер — байты UTF-8, а не длина строки: кириллица в length занижена вдвое.
 * TextEncoder, а не Buffer: вход пакета работает и в браузере.
 */
export function parseWorkloadsSection(input: unknown): WorkloadsParseResult {
  let json: string | undefined;
  try {
    json = JSON.stringify(input);
  } catch {
    return { ok: false, reason: "not_serializable" };
  }
  const bytes = json === undefined ? 0 : utf8.encode(json).length;
  if (bytes > WORKLOADS_MAX_SECTION_BYTES) {
    return { ok: false, reason: `too_large: ${bytes} > ${WORKLOADS_MAX_SECTION_BYTES} bytes` };
  }

  const parsed = workloadsSectionSchema.safeParse(input);
  if (!parsed.success) {
    const issue = parsed.error.issues[0]!;
    return { ok: false, reason: `${issue.path.join(".") || "section"}: ${issue.message}` };
  }
  return { ok: true, section: parsed.data };
}
