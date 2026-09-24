package hoststate

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Протокол web → подписант (ADR-0092, решение 2). Типы живут здесь, рядом с
// форматом пакета: подписант и его тесты собирают ответ этими типами, а web
// сверяет свой разбор с signer-api.json, который генерируется из них же.

// SignRequest — тело POST /v1/sign. State — без значений секретов, Secrets —
// ссылки на них, Grants — конверты грантов корня (web их не хранит и шлёт
// пустой список). SeqHint — последний номер, принятый агентом, из его такта.
type SignRequest struct {
	HostID           string            `json:"hostId"`
	AgentFingerprint string            `json:"agentFingerprint"`
	Content          string            `json:"content"`
	SeqHint          int64             `json:"seqHint"`
	State            json.RawMessage   `json:"state"`
	Secrets          []string          `json:"secrets"`
	Grants           []json.RawMessage `json:"grants"`
}

const (
	SignStatusSigned  = "signed"
	SignStatusRefused = "refused"
)

// Violation — одно нарушение политики: приложение и правило, текстом для
// человека (карточка релиза и сервера).
type Violation struct {
	App  string `json:"app"`
	Rule string `json:"rule"`
}

// SignResponse — ответ 200 на POST /v1/sign. Два вида с разным набором полей:
// signed — {status, seq, payloadSha256, certSerial, certNotAfter, bundle},
// refused — {status, reason, violations}. Сериализация отдаёт ровно поля
// своего вида: лишнее нулевое поле web прочитал бы как «пакет есть, пустой».
// Теги — имена на проводе; разбирается любой вид обычным json.Unmarshal.
type SignResponse struct {
	Status        string      `json:"status"`
	Seq           int64       `json:"seq"`
	PayloadSHA256 string      `json:"payloadSha256"`
	CertSerial    int64       `json:"certSerial"`
	CertNotAfter  string      `json:"certNotAfter"`
	Bundle        Bundle      `json:"bundle"`
	Reason        string      `json:"reason"`
	Violations    []Violation `json:"violations"`
}

func (r SignResponse) MarshalJSON() ([]byte, error) {
	switch r.Status {
	case SignStatusSigned:
		if r.Seq < 1 || r.Bundle.Envelope.PayloadType == "" || r.Bundle.Certificate.PayloadType == "" {
			return nil, errors.New("подписанный ответ без номера или пакета")
		}
		return marshalNoEscape(struct {
			Status        string `json:"status"`
			Seq           int64  `json:"seq"`
			PayloadSHA256 string `json:"payloadSha256"`
			CertSerial    int64  `json:"certSerial"`
			CertNotAfter  string `json:"certNotAfter"`
			Bundle        Bundle `json:"bundle"`
		}{r.Status, r.Seq, r.PayloadSHA256, r.CertSerial, r.CertNotAfter, r.Bundle})
	case SignStatusRefused:
		if r.Reason == "" {
			return nil, errors.New("отказ без причины")
		}
		// Отказ без нарушений по приложениям (грант, номер) — пустой список,
		// а не null: разбор web не различает эти случаи отдельной веткой.
		violations := r.Violations
		if violations == nil {
			violations = []Violation{}
		}
		return marshalNoEscape(struct {
			Status     string      `json:"status"`
			Reason     string      `json:"reason"`
			Violations []Violation `json:"violations"`
		}{r.Status, r.Reason, violations})
	}
	return nil, fmt.Errorf("status ответа подписанта %q", r.Status)
}

// Health — тело GET /healthz. Без сертификата полей сертификата нет вовсе:
// сторож выкатов отличает «сертификата нет» от «истёк». Reason — почему
// подписант не готов.
type Health struct {
	OK           bool   `json:"ok"`
	CertSerial   int64  `json:"certSerial,omitempty"`
	CertNotAfter string `json:"certNotAfter,omitempty"`
	ExpiresSoon  bool   `json:"expiresSoon"`
	Reason       string `json:"reason,omitempty"`
}
