package hoststate

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Reason — код отказа или удержания. Строки стабильны: их пишет в базу SQL,
// показывает web и докладывает агент (ADR-0093, решение 7), и переименование
// ломает разбор на платформе молча. Форма — `^[a-z_]{1,64}$`, её же
// проверяет `deploy_record_agent_signing`.
type Reason string

// Отказы, которые выдаёт Verify.
const (
	ReasonEnvelopeMalformed   Reason = "envelope_malformed"
	ReasonSignatureInvalid    Reason = "signature_invalid"
	ReasonCertInvalid         Reason = "cert_invalid"
	ReasonCertNotFromRoot     Reason = "cert_not_from_root"
	ReasonCertNotYetValid     Reason = "cert_not_yet_valid"
	ReasonCertExpired         Reason = "cert_expired"
	ReasonCertValidityTooLong Reason = "cert_validity_too_long"
	ReasonCertPurpose         Reason = "cert_purpose"
	ReasonCertSuperseded      Reason = "cert_superseded"
	ReasonUnsupportedContent  Reason = "unsupported_content"
	ReasonPayloadMalformed    Reason = "payload_malformed"
	ReasonFingerprintMismatch Reason = "fingerprint_mismatch"
	ReasonSeqRollback         Reason = "seq_rollback"
	ReasonSecretsMismatch     Reason = "secrets_mismatch"
	ReasonGrantInvalid        Reason = "grant_invalid"
)

// Отказы, которые выдаёт сам агент вокруг Verify: строгий разбор собранного
// состояния, корни из сборки, файл защёлок. Живут здесь, чтобы весь словарь
// контракта был в одном месте.
const (
	ReasonStateMalformed    Reason = "state_malformed"
	ReasonTrustRootsInvalid Reason = "trust_roots_invalid"
	ReasonLatchUnreadable   Reason = "latch_unreadable"
	ReasonLatchWriteFailed  Reason = "latch_write_failed"
)

// Причины удержания (статус held): пакета в ответе нет. ReasonNoBundle — нет
// и объяснения; остальные — значения поля stateWithheld ответа платформы.
const (
	ReasonNoBundle             Reason = "no_bundle"
	ReasonSignerUnavailable    Reason = "signer_unavailable"
	ReasonSignerRefused        Reason = "signer_refused"
	ReasonSignerNotConfigured  Reason = "signer_not_configured"
	ReasonProtocolIncompatible Reason = "protocol_incompatible"
)

// RefusalError — отказ с кодом контракта. Код нужен вызывающему, а не только
// текст: подписанту истёкший сертификат значит «не готов, 503», а сертификат
// не от корня — ошибку настройки.
type RefusalError struct {
	Reason Reason
	Detail string
}

func (e *RefusalError) Error() string {
	return string(e.Reason) + ": " + e.Detail
}

const (
	// PurposeHostState — назначение сертификата, без которого рабочий ключ не
	// подписывает состояние.
	PurposeHostState = "host-state"

	// maxCertValidity — предел срока сертификата (ADR-0092, решение 7): отзыва
	// нет, и столько живёт украденный рабочий ключ. Выпуск по умолчанию — 30
	// дней; предел не даёт ошибке церемонии выпустить «вечный».
	maxCertValidity = 45 * 24 * time.Hour

	// notBeforeSkew — допуск часов хоста на notBefore: сертификат, выпущенный
	// минуту назад, не должен отвергаться хостом с отстающими часами. На
	// notAfter допуска нет — там он лишь продлил бы жизнь ключу.
	notBeforeSkew = 5 * time.Minute
)

// Certificate — нагрузка сертификата рабочего ключа. Порядок полей — порядок
// сериализации при выпуске.
type Certificate struct {
	V         int      `json:"v"`
	Serial    int64    `json:"serial"`
	KeyID     string   `json:"keyId"`
	PublicKey string   `json:"publicKey"`
	NotBefore string   `json:"notBefore"`
	NotAfter  string   `json:"notAfter"`
	Purposes  []string `json:"purposes"`
}

// Payload — подписанная нагрузка состояния хоста. Body разбирается по
// payloadType; для host-state/0 это BodyV0.
//
// hostId — для учёта и счётчика подписанта: агент его не закрепляет
// (ADR-0092, решение 4), привязка к хосту — только отпечаток агента.
type Payload struct {
	HostID           string          `json:"hostId"`
	AgentFingerprint string          `json:"agentFingerprint"`
	Seq              int64           `json:"seq"`
	IssuedAt         string          `json:"issuedAt"`
	Body             json.RawMessage `json:"body"`
}

// BodyV0 — тело host-state/0. State остаётся сырым: строго в DesiredState его
// разбирает сам агент — общий пакет от кода агента не зависит. Grants —
// конверты грантов корня как есть: каждый проверяется своей подписью.
type BodyV0 struct {
	State   json.RawMessage   `json:"state"`
	Secrets []string          `json:"secrets"`
	Grants  []json.RawMessage `json:"grants"`
}

// Bundle — пакет подписи: так его хранит платформа и получает агент.
type Bundle struct {
	Envelope    signenv.Envelope `json:"envelope"`
	Certificate signenv.Envelope `json:"certificate"`
}

// Latch — защёлки агента между проверками (ADR-0093, решение 5). Приходит на
// вход и возвращается обновлённой: пакет чистый, запись файла с fsync —
// забота агента.
type Latch struct {
	// AgentFingerprint — чей это файл. Защёлка другого отпечатка — след
	// прежней установки агента, и проверка начинается заново.
	AgentFingerprint string `json:"agentFingerprint"`
	// Seq и PayloadSHA256 — последний принятый пакет: меньший seq — откат,
	// равный — только те же байты (повторная доставка).
	Seq           int64  `json:"seq"`
	PayloadSHA256 string `json:"payloadSha256"`
	// MaxCertSerial — наибольший serial сертификата из принятых пакетов: всё
	// меньшее закрыто (отзыва списком нет, ADR-0092, решение 8).
	MaxCertSerial int64 `json:"maxCertSerial"`
}

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// Имена в ссылках — те же правила, что агент применяет к полям состояния
	// (apply.go safeSlug и safeEnvKey, registry.go safeRegistryHost): ссылка,
	// которую агент не смог бы применить, отвергается ещё при подписи.
	refSlugRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
	refEnvNameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	refRegistryRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
)

// parseUTC — момент в RFC 3339 строго с «Z»: смещение не ошибка формата, но две
// записи одного момента давали бы разные байты, и сравнение по строке на
// другой стороне разошлось бы.
func parseUTC(s string) (time.Time, error) {
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, errors.New("время не в UTC (ожидается суффикс Z): " + s)
	}
	return time.Parse(time.RFC3339, s)
}

func formatUTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// secretRef — разобранная ссылка на секрет.
type secretRef struct {
	kind     string // env, gitKey, gitToken, registryToken, objectStorage
	slug     string
	name     string
	registry string
}

func parseSecretRef(ref string) (secretRef, bool) {
	parts := strings.Split(ref, "/")
	switch {
	case len(parts) == 4 && parts[0] == "app" && parts[2] == "env":
		if refSlugRe.MatchString(parts[1]) && refEnvNameRe.MatchString(parts[3]) {
			return secretRef{kind: "env", slug: parts[1], name: parts[3]}, true
		}
	case len(parts) == 3 && parts[0] == "app" && (parts[2] == "gitKey" || parts[2] == "gitToken"):
		if refSlugRe.MatchString(parts[1]) {
			return secretRef{kind: parts[2], slug: parts[1]}, true
		}
	case len(parts) == 3 && parts[0] == "registry" && parts[2] == "token":
		if refRegistryRe.MatchString(parts[1]) {
			return secretRef{kind: "registryToken", registry: parts[1]}, true
		}
	case ref == "objectStorage/secretAccessKey":
		return secretRef{kind: "objectStorage"}, true
	}
	return secretRef{}, false
}

// ValidSecretRef — соответствует ли строка грамматике ссылок на секреты:
// `app/<slug>/env/<NAME>`, `app/<slug>/gitKey`, `app/<slug>/gitToken`,
// `registry/<host>/token`, `objectStorage/secretAccessKey`.
func ValidSecretRef(ref string) bool {
	_, ok := parseSecretRef(ref)
	return ok
}
