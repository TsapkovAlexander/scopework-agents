package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Приём подписанного желаемого состояния (ADR-0092, ADR-0093, решения 4–7).
//
// Правило приёма берётся из бинаря (корни сборки), а не из ответа: агент с
// корнями не применяет неподписанное ни в такте, ни на запасном /state, ни
// после рестарта. Поэтому проверка живёт в клиенте, одна на оба пути, а
// main.go видит только признак «состояние принято».
//
// ОТКАЗ — НЕ ОШИБКА ДОСТАВКИ. Ошибка из Tick сделала бы такт недоставленным:
// ложная квитанция, стоящий курсор трафика, ни отметки о жизни, ни интервала.
// Успех с обнулённым состоянием без признака снёс бы стеки. Поэтому при любом
// непринятии состояние обнуляется, Accepted = false, а ошибки нет.

// SigningReport — итог проверки, поле signing такта и /state. Состояние, а не
// событие: уходит следующим запросом и пишется платформой поверх прежнего.
type SigningReport struct {
	// Status — accepted, refused или held (пакета в ответе не было).
	Status string `json:"status"`
	// Reason — код из словаря hoststate; у принятого пуст.
	Reason string `json:"reason,omitempty"`
	// Seq — номер пакета из ответа; 0 — пакета не было или номер не прочитан.
	Seq int64 `json:"seq"`
	// LastAcceptedSeq — последний принятый номер. Подсказка подписанту: ею
	// восстанавливается его хранилище номеров (ADR-0092).
	LastAcceptedSeq int64 `json:"lastAcceptedSeq"`
	// At — момент проверки по часам агента, RFC 3339 UTC.
	At string `json:"at"`
}

const (
	signingAccepted = "accepted"
	signingRefused  = "refused"
	signingHeld     = "held"
)

// signedStateWire — поле signedState ответа платформы.
type signedStateWire struct {
	Content string            `json:"content"`
	Bundle  json.RawMessage   `json:"bundle"`
	Secrets map[string]string `json:"secrets"`
}

// withheldReasons — объяснения платформы, почему пакета нет. Незнакомое
// значение не пересказывается: в доклад уходит только словарь, иначе поле
// ответа стало бы каналом произвольного текста в базу.
var withheldReasons = map[string]hoststate.Reason{
	string(hoststate.ReasonSignerUnavailable):    hoststate.ReasonSignerUnavailable,
	string(hoststate.ReasonSignerRefused):        hoststate.ReasonSignerRefused,
	string(hoststate.ReasonSignerNotConfigured):  hoststate.ReasonSignerNotConfigured,
	string(hoststate.ReasonProtocolIncompatible): hoststate.ReasonProtocolIncompatible,
}

// agentProtocol — объявление этой сборки. Обёртки объявляются только при
// исправных непустых корнях: с битыми агент ничего не проверяет и не должен
// выглядеть для платформы проверяющим.
func agentProtocol() hoststate.Protocol {
	roots, err := StateRootsStatus()
	return hoststate.AgentProtocol(err == nil && len(roots) > 0)
}

// pendingSigning — итог предыдущего ответа для доклада. nil до первого итога
// и у агента без корней: такой агент итогов не заводит вовсе.
func (c *Client) pendingSigning() *SigningReport {
	c.signingMu.Lock()
	defer c.signingMu.Unlock()
	if c.lastSigning == nil {
		return nil
	}
	report := *c.lastSigning
	return &report
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// acceptState решает, что из ответа применять. Единственное место, где
// ответ платформы становится состоянием к применению.
func (c *Client) acceptState(fingerprint string, st *DesiredState, signed json.RawMessage, withheld string) {
	roots, rootsErr := StateRootsStatus()
	if rootsErr == nil && len(roots) == 0 {
		// Корней нет — как до подписи. Ответ без списка приложений — не
		// «снять всё», а старая или сломанная платформа: заменять им
		// состояние нельзя.
		st.Accepted = st.Apps != nil
		return
	}

	accepted, report, detail := c.verifySigned(fingerprint, roots, rootsErr, signed, withheld)
	report.At = c.clock().UTC().Format(time.RFC3339)
	// Плоские поля ответа агенту с корнями не достаются ни при каком исходе.
	*st = DesiredState{}
	if accepted != nil {
		*st = *accepted
		st.Accepted = true
	}
	c.recordSigning(report, detail)
}

// verifySigned проверяет пакет и возвращает состояние (nil — не принято),
// итог для доклада и подробность для журнала агента.
func (c *Client) verifySigned(
	fingerprint string,
	roots []ed25519.PublicKey,
	rootsErr error,
	signed json.RawMessage,
	withheld string,
) (*DesiredState, SigningReport, string) {
	refuse := func(r SigningReport, reason hoststate.Reason, detail string) (*DesiredState, SigningReport, string) {
		r.Status, r.Reason = signingRefused, string(reason)
		return nil, r, detail
	}
	if rootsErr != nil {
		return refuse(SigningReport{}, hoststate.ReasonTrustRootsInvalid, rootsErr.Error())
	}

	// Каталог не задан при корнях — отказ, а не приём без защёлок: без них
	// повтор старого пакета неотличим от свежего.
	latch, latchErr := hoststate.Latch{}, errors.New("каталог состояния агента не задан")
	if c.stateDir != "" {
		latch, latchErr = loadStateLatch(c.stateDir, fingerprint)
	}
	report := SigningReport{LastAcceptedSeq: latch.Seq}

	if absentJSON(signed) {
		reason, ok := withheldReasons[withheld]
		if !ok {
			reason = hoststate.ReasonNoBundle
		}
		report.Status, report.Reason = signingHeld, string(reason)
		return nil, report, "платформа не прислала подписанного состояния"
	}
	if latchErr != nil {
		return refuse(report, hoststate.ReasonLatchUnreadable, latchErr.Error())
	}

	var wire signedStateWire
	if err := signenv.DecodeStrict(signed, &wire); err != nil {
		if isUnknownFieldError(err) {
			return refuse(report, hoststate.ReasonUnsupportedContent, "signedState: "+err.Error())
		}
		return refuse(report, hoststate.ReasonEnvelopeMalformed, "signedState: "+err.Error())
	}
	// Сначала сертификат и подпись, потом метка content (ADR-0092, решение 4:
	// сертификат — первым). Метка — поле ответа, подписью не покрыто: отказ по
	// ней раньше проверки пакета называл бы «содержимое новее агента» то, что
	// подписано чужим ключом или не подписано вовсе, и доклад врал бы о
	// причине. Подписанная версия — payloadType, её сверяет Verify.
	res := hoststate.Verifier{Roots: roots, AgentFingerprint: fingerprint, Now: c.clock}.
		Verify(latch, hoststate.Input{Bundle: wire.Bundle, Secrets: wire.Secrets})
	report.Seq = res.Seq
	if res.Reason != "" {
		return refuse(report, res.Reason, res.Detail)
	}
	if wire.Content != hoststate.ContentV0 {
		return refuse(report, hoststate.ReasonUnsupportedContent,
			fmt.Sprintf("содержимое %q, агент исполняет %s", tail(wire.Content, 64), hoststate.ContentV0))
	}

	state, reason, err := decodeSignedDesiredState(res.State)
	if err != nil {
		return refuse(report, reason, err.Error())
	}
	attachAllowances(&state, res.AllowancesByCompose)
	state.SignedPayloadSHA256 = res.PayloadSHA256

	// Защёлка пишется только за принятым целиком пакетом, и до того, как
	// состояние уйдёт в применение: иначе сбой после применения оставил бы
	// на диске прежний номер.
	if err := saveStateLatch(c.stateDir, res.Next); err != nil {
		return refuse(report, hoststate.ReasonLatchWriteFailed, err.Error())
	}
	report.Status, report.LastAcceptedSeq = signingAccepted, res.Next.Seq
	return &state, report, ""
}

// decodeSignedDesiredState — строгий разбор собранного состояния. Незнакомое
// поле — «содержимое новее агента» (ADR-0093, решение 6): понятое наполовину
// применилось бы наполовину. Прочая ошибка — порча состояния.
func decodeSignedDesiredState(raw []byte) (DesiredState, hoststate.Reason, error) {
	var st DesiredState
	if err := signenv.DecodeStrict(raw, &st); err != nil {
		if isUnknownFieldError(err) {
			return DesiredState{}, hoststate.ReasonUnsupportedContent, fmt.Errorf("состояние: %w", err)
		}
		return DesiredState{}, hoststate.ReasonStateMalformed, fmt.Errorf("состояние: %w", err)
	}
	// Снять всё можно только подписанным пустым списком: отсутствие списка
	// неотличимо от сбоя сборки состояния.
	if st.Apps == nil {
		return DesiredState{}, hoststate.ReasonStateMalformed, errors.New("в состоянии нет списка apps")
	}
	return st, "", nil
}

// attachAllowances раздаёт послабления проверенных грантов приложениям с теми
// же байтами compose (С1.5, ADR-0092, решение 11). Приложение из репозитория
// гранта не получает: его описание стека читается из репозитория, а не из
// подписанных байтов, и digest пустой строки ничего о нём не говорит.
func attachAllowances(st *DesiredState, byCompose map[string][]composeguard.Allowance) {
	for i := range st.Apps {
		app := &st.Apps[i]
		if app.FromGit() || app.Compose == "" {
			continue
		}
		sum := sha256.Sum256([]byte(app.Compose))
		app.Allowances = byCompose[hex.EncodeToString(sum[:])]
	}
}

// recordSigning запоминает итог для следующего запроса и пишет его в журнал
// агента — только при смене, чтобы удержание на время недоступного
// подписанта не писало одну и ту же строку каждый такт.
func (c *Client) recordSigning(r SigningReport, detail string) {
	c.signingMu.Lock()
	prev := c.lastSigning
	c.lastSigning = &r
	c.signingMu.Unlock()

	if prev != nil && prev.Status == r.Status && prev.Reason == r.Reason && prev.Seq == r.Seq {
		return
	}
	switch r.Status {
	case signingAccepted:
		fmt.Printf("подписанное состояние принято: seq %d\n", r.Seq)
	case signingHeld:
		fmt.Fprintf(os.Stderr, "подписанного состояния нет (%s): держу прежнее\n", r.Reason)
	default:
		fmt.Fprintf(os.Stderr, "подписанное состояние отвергнуто (%s, seq %d): %s; держу прежнее\n",
			r.Reason, r.Seq, tail(detail, 500))
	}
}

func absentJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// isUnknownFieldError — ошибка DisallowUnknownFields. Отдельного типа у неё в
// encoding/json нет, только текст.
func isUnknownFieldError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "json: unknown field ")
}
