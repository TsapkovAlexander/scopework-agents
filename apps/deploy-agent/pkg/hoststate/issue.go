package hoststate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Выпуск — та же проверка формата, что при приёме: CLI корня и подписант не
// должны уметь выпустить то, что агент отвергнет. Иначе ошибка выпуска видна
// только отказами на хостах клиентов.

// IssueCertificate выпускает сертификат рабочего ключа, подписанный корнем.
func IssueCertificate(rootPriv ed25519.PrivateKey, serial int64, workPub ed25519.PublicKey, notBefore, notAfter time.Time) (signenv.Envelope, error) {
	if len(workPub) != ed25519.PublicKeySize {
		return signenv.Envelope{}, fmt.Errorf("публичный ключ %d байт, ожидалось %d", len(workPub), ed25519.PublicKeySize)
	}
	cert := Certificate{
		V:         1,
		Serial:    serial,
		KeyID:     signenv.KeyID(workPub),
		PublicKey: base64.StdEncoding.EncodeToString(workPub),
		NotBefore: formatUTC(notBefore),
		NotAfter:  formatUTC(notAfter),
		Purposes:  []string{PurposeHostState},
	}
	if _, _, err := validateCert(cert); err != nil {
		return signenv.Envelope{}, err
	}
	raw, err := marshalNoEscape(cert)
	if err != nil {
		return signenv.Envelope{}, err
	}
	return signenv.Sign(rootPriv, PayloadTypeCert, raw), nil
}

// HostState — что подписывает подписант: заголовок и тело host-state/0.
type HostState struct {
	HostID           string
	AgentFingerprint string
	Seq              int64
	IssuedAt         time.Time
	// State — желаемое состояние без значений секретов.
	State json.RawMessage
	// Secrets — ссылки на секреты; порядок любой, выпуск сортирует по байтам.
	Secrets []string
	// Grants — конверты грантов корня. Их подпись подписант проверяет
	// VerifyGrant до выпуска: здесь корней нет, проверяется только форма.
	Grants []json.RawMessage
}

// SignState подписывает состояние хоста рабочим ключом как host-state/0.
//
// Сортировка ссылок — здесь, а не у web: в подписанных байтах порядок обязан
// быть побайтным, а порядок строк в Postgres зависит от правила сравнения базы.
func SignState(workPriv ed25519.PrivateKey, hs HostState) (signenv.Envelope, error) {
	secrets := append([]string{}, hs.Secrets...)
	sort.Strings(secrets)
	// Пустой список, а не null: строгий разбор агента требует поле grants.
	grants := append([]json.RawMessage{}, hs.Grants...)
	for i, g := range grants {
		if err := checkGrantForm(g); err != nil {
			return signenv.Envelope{}, fmt.Errorf("грант %d: %w", i, err)
		}
	}
	body := BodyV0{State: hs.State, Secrets: secrets, Grants: grants}
	if err := validateBodyV0(body); err != nil {
		return signenv.Envelope{}, err
	}
	// Ссылка без цели подписанию не подлежит: агент такой пакет не соберёт.
	dummy := make(map[string]string, len(secrets))
	for _, r := range secrets {
		dummy[r] = ""
	}
	if _, err := AssembleStateV0(body.State, secrets, dummy); err != nil {
		return signenv.Envelope{}, err
	}
	bodyRaw, err := marshalNoEscape(body)
	if err != nil {
		return signenv.Envelope{}, err
	}
	p := Payload{
		HostID:           hs.HostID,
		AgentFingerprint: hs.AgentFingerprint,
		Seq:              hs.Seq,
		IssuedAt:         formatUTC(hs.IssuedAt),
		Body:             bodyRaw,
	}
	if err := validateHeader(p); err != nil {
		return signenv.Envelope{}, err
	}
	raw, err := marshalNoEscape(p)
	if err != nil {
		return signenv.Envelope{}, err
	}
	return signenv.Sign(workPriv, PayloadTypeHostStateV0, raw), nil
}

// validateCert — форма сертификата; возвращает рабочий ключ. Срок длиннее
// предела — свой код: это ошибка церемонии, а не порча документа.
func validateCert(c Certificate) (ed25519.PublicKey, Reason, error) {
	invalid := func(err error) (ed25519.PublicKey, Reason, error) { return nil, ReasonCertInvalid, err }
	if c.V != 1 {
		return invalid(fmt.Errorf("версия сертификата %d", c.V))
	}
	if c.Serial < 1 {
		return invalid(errors.New("serial сертификата меньше 1"))
	}
	key, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return invalid(errors.New("publicKey не base64 32 байт"))
	}
	if c.KeyID != signenv.KeyID(key) {
		return invalid(errors.New("keyId не равен sha256(publicKey)"))
	}
	nb, err := parseUTC(c.NotBefore)
	if err != nil {
		return invalid(fmt.Errorf("notBefore: %w", err))
	}
	na, err := parseUTC(c.NotAfter)
	if err != nil {
		return invalid(fmt.Errorf("notAfter: %w", err))
	}
	if !na.After(nb) {
		return invalid(errors.New("notAfter не позже notBefore"))
	}
	if c.Purposes == nil {
		return invalid(errors.New("нет purposes"))
	}
	if na.Sub(nb) > maxCertValidity {
		return nil, ReasonCertValidityTooLong, fmt.Errorf("срок сертификата %s..%s больше 45 дней", c.NotBefore, c.NotAfter)
	}
	return ed25519.PublicKey(key), "", nil
}

func validateHeader(p Payload) error {
	if !uuidRe.MatchString(p.HostID) {
		return errors.New("hostId не uuid в нижнем регистре")
	}
	if !hex64Re.MatchString(p.AgentFingerprint) {
		return errors.New("agentFingerprint не hex64")
	}
	if p.Seq < 1 {
		return errors.New("seq меньше 1")
	}
	if _, err := parseUTC(p.IssuedAt); err != nil {
		return fmt.Errorf("issuedAt: %w", err)
	}
	return nil
}

func validateBodyV0(b BodyV0) error {
	if firstNonSpace(b.State) != '{' || !json.Valid(b.State) {
		return errors.New("state не JSON-объект")
	}
	if b.Secrets == nil {
		return errors.New("нет secrets")
	}
	if b.Grants == nil {
		return errors.New("нет grants")
	}
	for i, r := range b.Secrets {
		if !ValidSecretRef(r) {
			return fmt.Errorf("ссылка %q не по грамматике", r)
		}
		// Строго возрастающий порядок — и сортировка, и отсутствие повторов.
		if i > 0 && b.Secrets[i-1] >= r {
			return errors.New("secrets не отсортированы по байтам или с повтором")
		}
	}
	return nil
}

func firstNonSpace(b []byte) byte {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return c
	}
	return 0
}
