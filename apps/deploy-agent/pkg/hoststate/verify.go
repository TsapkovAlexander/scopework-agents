package hoststate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Verifier проверяет пакет подписи. Корни передаются снаружи: боевые вшиты в
// бинарь агента при сборке, тестовые подставляет тест.
type Verifier struct {
	Roots []ed25519.PublicKey
	// AgentFingerprint — свой отпечаток агента, sha256 от base64 ключа.
	AgentFingerprint string
	// Now — часы; nil — системные. Сертификат — единственное, что проверка
	// сверяет со временем: у манифеста срока нет (ADR-0092, решение 3).
	Now func() time.Time
}

// Input — то, что пришло в ответе такта: пакет и значения секретов рядом с
// ним, вне подписи.
type Input struct {
	Bundle  []byte
	Secrets map[string]string
}

// Result — итог проверки. Reason пустой — пакет принят.
type Result struct {
	// Next — защёлка для записи на диск. При любом отказе равна переданной:
	// отвергнутый пакет не оставляет следа, иначе один подложный пакет
	// поднимал бы номер или serial и запирал агента от честных.
	Next   Latch
	Reason Reason
	// Detail — подробность для журнала агента; в доклад платформе уходит Reason.
	Detail string

	// Заполняются, как только известны, — докладу об отказе тоже нужны номер
	// пакета и serial сертификата. PayloadSHA256 — sha256 байтов нагрузки
	// DSSE: тот же хеш пишут журнал отправленного и локальный журнал агента.
	Seq           int64
	PayloadSHA256 string
	CertSerial    int64

	// Только у принятого пакета. State — собранное состояние с подставленными
	// значениями секретов, для строгого разбора агентом. AllowancesByCompose —
	// послабления из проверенных грантов по hex(sha256) байтов compose.
	State               json.RawMessage
	AllowancesByCompose map[string][]composeguard.Allowance
}

type bundleWire struct {
	Envelope    json.RawMessage `json:"envelope"`
	Certificate json.RawMessage `json:"certificate"`
}

func (v Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify проверяет пакет по ADR-0092, решение 4. Порядок — часть контракта:
// причина отказа должна совпадать у агента и в фикстурах, по которым web учится
// её показывать.
func (v Verifier) Verify(prev Latch, in Input) Result {
	res := Result{Next: prev}
	fail := func(r Reason, format string, args ...any) Result {
		res.Reason = r
		res.Detail = fmt.Sprintf(format, args...)
		return res
	}
	// Защёлка другого отпечатка — след прежней установки агента на этом
	// сервере: переустановка — действие root, и проверка начинается заново.
	latch := prev
	if latch.AgentFingerprint != v.AgentFingerprint {
		latch = Latch{}
	}

	var b bundleWire
	if err := signenv.DecodeStrict(in.Bundle, &b); err != nil {
		return fail(ReasonEnvelopeMalformed, "пакет не разбирается: %v", err)
	}
	if isAbsent(b.Envelope) || isAbsent(b.Certificate) {
		return fail(ReasonEnvelopeMalformed, "в пакете нет envelope или certificate")
	}

	// 1. Сертификат рабочего ключа.
	cert, workKey, err := VerifyCertificate(b.Certificate, v.Roots, v.now())
	if err != nil {
		var refusal *RefusalError
		if errors.As(err, &refusal) {
			return fail(refusal.Reason, "%s", refusal.Detail)
		}
		return fail(ReasonCertInvalid, "%v", err)
	}
	res.CertSerial = cert.Serial
	if cert.Serial < latch.MaxCertSerial {
		return fail(ReasonCertSuperseded, "serial %d при принятом %d", cert.Serial, latch.MaxCertSerial)
	}

	// 2. Конверт состояния.
	env, err := signenv.Parse(b.Envelope)
	if err != nil {
		return fail(ReasonEnvelopeMalformed, "конверт состояния: %v", err)
	}
	sum := sha256.Sum256(env.Payload)
	payloadSHA := hex.EncodeToString(sum[:])
	res.PayloadSHA256 = payloadSHA
	if env.PayloadType != PayloadTypeHostStateV0 {
		return fail(ReasonUnsupportedContent, "незнакомый payloadType %q", env.PayloadType)
	}
	if !env.Verify(workKey) {
		return fail(ReasonSignatureInvalid, "подпись состояния не проверяется ключом сертификата")
	}

	// 3. Строгий разбор нагрузки и привязка к агенту.
	payload, body, reason, detail := parsePayloadV0(env.Payload)
	if payload != nil {
		res.Seq = payload.Seq
	}
	if reason != "" {
		return fail(reason, "%s", detail)
	}
	if payload.AgentFingerprint != v.AgentFingerprint {
		return fail(ReasonFingerprintMismatch, "пакет для отпечатка %s", payload.AgentFingerprint)
	}

	// 4. Номер.
	if payload.Seq < latch.Seq || (payload.Seq == latch.Seq && payloadSHA != latch.PayloadSHA256) {
		return fail(ReasonSeqRollback, "seq %d при принятом %d", payload.Seq, latch.Seq)
	}

	// 5. Гранты корня: негодный грант — отказ всему пакету, а не пропуск
	// одного послабления (ADR-0092, решение 11).
	allowances := make(map[string][]composeguard.Allowance, len(body.Grants))
	for i, raw := range body.Grants {
		g, err := VerifyGrant(raw, v.Roots)
		if err != nil {
			return fail(ReasonGrantInvalid, "грант %d: %v", i, err)
		}
		allowances[g.ComposeSHA256] = append(allowances[g.ComposeSHA256], g.Allowances...)
	}

	// 6. Набор значений секретов.
	if !SecretValuesMatch(body.Secrets, in.Secrets) {
		return fail(ReasonSecretsMismatch, "подписано ссылок %d, значений пришло %d", len(body.Secrets), len(in.Secrets))
	}
	state, err := AssembleStateV0(body.State, body.Secrets, in.Secrets)
	if err != nil {
		return fail(ReasonPayloadMalformed, "состояние не собирается: %v", err)
	}

	// Защёлки поднимаются только здесь, вместе с принятым пакетом целиком.
	res.Next = Latch{
		AgentFingerprint: v.AgentFingerprint,
		Seq:              payload.Seq,
		PayloadSHA256:    payloadSHA,
		MaxCertSerial:    max(latch.MaxCertSerial, cert.Serial),
	}
	res.State = state
	res.AllowancesByCompose = allowances
	return res
}

// VerifyCertificate — проверка сертификата рабочего ключа, та же, что в
// Verify: подписант прогоняет ею свой сертификат при старте, чтобы не
// выпускать пакеты, которые агенты отвергнут. Отказ — *RefusalError с кодом.
//
// Защёлки serial здесь нет: она у агента и зависит от принятых им пакетов.
func VerifyCertificate(raw []byte, roots []ed25519.PublicKey, now time.Time) (Certificate, ed25519.PublicKey, error) {
	refuse := func(r Reason, format string, args ...any) (Certificate, ed25519.PublicKey, error) {
		return Certificate{}, nil, &RefusalError{Reason: r, Detail: fmt.Sprintf(format, args...)}
	}
	env, err := signenv.Parse(raw)
	if err != nil {
		return refuse(ReasonCertInvalid, "сертификат: %v", err)
	}
	if env.PayloadType != PayloadTypeCert {
		return refuse(ReasonCertInvalid, "сертификат с типом %q", env.PayloadType)
	}
	if signedByRoot(env, roots) == nil {
		return refuse(ReasonCertNotFromRoot, "сертификат не подписан вшитым корнем (keyid %s)", env.KeyID)
	}
	var cert Certificate
	if err := signenv.DecodeStrict(env.Payload, &cert); err != nil {
		return refuse(ReasonCertInvalid, "сертификат не разбирается: %v", err)
	}
	key, reason, err := validateCert(cert)
	if err != nil {
		return refuse(reason, "сертификат %d: %v", cert.Serial, err)
	}
	nb, _ := parseUTC(cert.NotBefore)
	na, _ := parseUTC(cert.NotAfter)
	if now.Before(nb.Add(-notBeforeSkew)) {
		return refuse(ReasonCertNotYetValid, "сертификат %d действует с %s", cert.Serial, cert.NotBefore)
	}
	if now.After(na) {
		return refuse(ReasonCertExpired, "сертификат %d истёк %s", cert.Serial, cert.NotAfter)
	}
	hasPurpose := false
	for _, p := range cert.Purposes {
		hasPurpose = hasPurpose || p == PurposeHostState
	}
	if !hasPurpose {
		return refuse(ReasonCertPurpose, "сертификат %d не для %s", cert.Serial, PurposeHostState)
	}
	return cert, key, nil
}

var (
	payloadKeys = map[string]bool{"hostId": true, "agentFingerprint": true, "seq": true, "issuedAt": true, "body": true}
	bodyV0Keys  = map[string]bool{"state": true, "secrets": true, "grants": true}
)

// parsePayloadV0 — строгий разбор нагрузки. Незнакомое поле отличается от
// битого: первое значит «содержимое новее агента» (unsupported_content,
// ADR-0093, решение 6), второе — ошибку подписанта.
func parsePayloadV0(raw []byte) (*Payload, *BodyV0, Reason, string) {
	if reason, detail := checkKeys(raw, payloadKeys, "нагрузке"); reason != "" {
		return nil, nil, reason, detail
	}
	var p Payload
	if err := signenv.DecodeStrict(raw, &p); err != nil {
		return nil, nil, ReasonPayloadMalformed, "нагрузка: " + err.Error()
	}
	if err := validateHeader(p); err != nil {
		return &p, nil, ReasonPayloadMalformed, "нагрузка: " + err.Error()
	}
	if reason, detail := checkKeys(p.Body, bodyV0Keys, "body"); reason != "" {
		return &p, nil, reason, detail
	}
	var body BodyV0
	if err := signenv.DecodeStrict(p.Body, &body); err != nil {
		return &p, nil, ReasonPayloadMalformed, "body: " + err.Error()
	}
	if err := validateBodyV0(body); err != nil {
		return &p, nil, ReasonPayloadMalformed, "body: " + err.Error()
	}
	return &p, &body, "", ""
}

// checkKeys — все ли поля объекта знакомы и есть ли обязательные.
func checkKeys(raw []byte, known map[string]bool, where string) (Reason, string) {
	var m map[string]json.RawMessage
	if err := signenv.DecodeStrict(raw, &m); err != nil || m == nil {
		return ReasonPayloadMalformed, where + ": не JSON-объект"
	}
	for k := range m {
		if !known[k] {
			return ReasonUnsupportedContent, fmt.Sprintf("незнакомое поле %q в %s", k, where)
		}
	}
	for k := range known {
		if _, ok := m[k]; !ok {
			return ReasonPayloadMalformed, fmt.Sprintf("нет поля %q в %s", k, where)
		}
	}
	return "", ""
}

func isAbsent(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}
