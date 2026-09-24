// Package signenv — конверт DSSE с подписью Ed25519 (обёртка dsse-ed25519/1,
// ADR-0082, решение 4; ADR-0092, решение 3).
//
// Пакет знает только конверт: байты, тип и одну подпись. Что лежит в нагрузке и
// чьим ключом её положено проверять, решает вызывающий (pkg/hoststate). Так
// один и тот же код разбирает сертификат, грант шаблона и состояние хоста.
//
// Подпись идёт над БАЙТАМИ нагрузки, а не над разобранным JSON: каноникализация
// JSON между Go и TypeScript расходится на числах и экранировании, и каждое
// расхождение было бы ложным отказом на хосте клиента.
package signenv

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Envelope — конверт в том виде, в каком он едет по сети и лежит в базе.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature — одна подпись конверта.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Parsed — разобранный конверт: base64 уже снят, подпись ещё НЕ проверена.
type Parsed struct {
	PayloadType string
	Payload     []byte
	KeyID       string
	Signature   []byte
}

// PAE — Pre-Authentication Encoding из спецификации DSSE. Тип входит в
// подписываемые байты, поэтому подпись сертификата не переносится на состояние
// хоста с теми же байтами нагрузки.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// KeyID — hex(sha256) сырых 32 байт публичного ключа. Не путать с отпечатком
// агента: тот считается от base64-строки ключа (agent-signature.json).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Sign подписывает нагрузку. Ed25519 детерминирован, поэтому одинаковый вход
// даёт побайтно одинаковый конверт — на этом держатся фикстуры.
func Sign(priv ed25519.PrivateKey, payloadType string, payload []byte) Envelope {
	pub := priv.Public().(ed25519.PublicKey)
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: KeyID(pub),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, PAE(payloadType, payload))),
		}},
	}
}

// Parse разбирает конверт строго. Подпись требуется ровно одна: при нескольких
// пришлось бы решать, какой из них верить, а это уже политика, которой в
// обёртке быть не должно.
func Parse(raw []byte) (Parsed, error) {
	var env Envelope
	if err := DecodeStrict(raw, &env); err != nil {
		return Parsed{}, fmt.Errorf("конверт не разбирается: %w", err)
	}
	if env.PayloadType == "" {
		return Parsed{}, errors.New("в конверте пустой payloadType")
	}
	if len(env.Signatures) != 1 {
		return Parsed{}, fmt.Errorf("подписей в конверте %d, допустима ровно одна", len(env.Signatures))
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Parsed{}, fmt.Errorf("payload не base64: %w", err)
	}
	s := env.Signatures[0]
	if id, err := hex.DecodeString(s.KeyID); err != nil || len(id) != sha256.Size || hex.EncodeToString(id) != s.KeyID {
		return Parsed{}, errors.New("keyid не hex(sha256) в нижнем регистре")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return Parsed{}, fmt.Errorf("sig не base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return Parsed{}, fmt.Errorf("длина подписи %d байт, ожидалось %d", len(sig), ed25519.SignatureSize)
	}
	return Parsed{PayloadType: env.PayloadType, Payload: payload, KeyID: s.KeyID, Signature: sig}, nil
}

// Verify — подписан ли конверт этим ключом. keyid обязан совпасть: по нему
// выбирают ключ, и верная подпись под чужим именем — признак подделки сборки,
// а не повод искать подходящий ключ перебором.
func (p Parsed) Verify(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize || p.KeyID != KeyID(pub) {
		return false
	}
	return ed25519.Verify(pub, PAE(p.PayloadType, p.Payload), p.Signature)
}

// DecodeStrict — разбор без незнакомых полей и без данных после значения.
// Боевой разбор ответа платформы молча отбрасывает незнакомое (ADR-0093,
// контекст), и для подписанного это недопустимо: понятая наполовину нагрузка
// применяется наполовину.
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("данные после JSON-значения")
	}
	return nil
}
