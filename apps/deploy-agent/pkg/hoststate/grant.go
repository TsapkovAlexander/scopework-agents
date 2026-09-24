package hoststate

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// TemplateGrant — грант корня шаблону (ADR-0092, решение 11): сверх политики
// шаблону разрешено только то, что подписал корень, и только для compose с
// этими байтами. Привязка — к digest, а не к имени шаблона: строка в
// deploy.templates иначе стала бы выходом за политику.
//
// Порядок полей — порядок сериализации при выпуске.
type TemplateGrant struct {
	V             int                      `json:"v"`
	ComposeSHA256 string                   `json:"composeSha256"`
	Allowances    []composeguard.Allowance `json:"allowances"`
	Notes         string                   `json:"notes"`
}

// IssueGrant выпускает грант, подписанный корнем. Выпуск — та же проверка
// формы, что при приёме: CLI корня не должен уметь выпустить грант, который
// агент отвергнет вместе со всем пакетом хоста.
func IssueGrant(rootPriv ed25519.PrivateKey, composeSHA256 string, allowances []composeguard.Allowance, notes string) (signenv.Envelope, error) {
	g := TemplateGrant{V: 1, ComposeSHA256: composeSHA256, Allowances: allowances, Notes: notes}
	if err := validateGrant(g); err != nil {
		return signenv.Envelope{}, err
	}
	raw, err := marshalNoEscape(g)
	if err != nil {
		return signenv.Envelope{}, err
	}
	return signenv.Sign(rootPriv, PayloadTypeGrant, raw), nil
}

// VerifyGrant проверяет грант корнями: тип, подпись, затем строгий разбор и
// форма. Нагрузка разбирается только после подписи — неподписанное не
// читается вовсе.
func VerifyGrant(raw []byte, roots []ed25519.PublicKey) (TemplateGrant, error) {
	env, err := parseGrantEnvelope(raw)
	if err != nil {
		return TemplateGrant{}, err
	}
	if signedByRoot(env, roots) == nil {
		return TemplateGrant{}, fmt.Errorf("грант не подписан корнем (keyid %s)", env.KeyID)
	}
	return decodeGrant(env.Payload)
}

// checkGrantForm — всё, кроме подписи: у выпуска состояния корней нет, их
// подпись подписант проверяет VerifyGrant до этого.
func checkGrantForm(raw []byte) error {
	env, err := parseGrantEnvelope(raw)
	if err != nil {
		return err
	}
	_, err = decodeGrant(env.Payload)
	return err
}

func parseGrantEnvelope(raw []byte) (signenv.Parsed, error) {
	env, err := signenv.Parse(raw)
	if err != nil {
		return signenv.Parsed{}, fmt.Errorf("грант: %w", err)
	}
	if env.PayloadType != PayloadTypeGrant {
		return signenv.Parsed{}, fmt.Errorf("грант с типом %q", env.PayloadType)
	}
	return env, nil
}

func decodeGrant(payload []byte) (TemplateGrant, error) {
	var g TemplateGrant
	if err := signenv.DecodeStrict(payload, &g); err != nil {
		return TemplateGrant{}, fmt.Errorf("грант не разбирается: %w", err)
	}
	if err := validateGrant(g); err != nil {
		return TemplateGrant{}, err
	}
	return g, nil
}

func validateGrant(g TemplateGrant) error {
	if g.V != 1 {
		return fmt.Errorf("версия гранта %d", g.V)
	}
	if !hex64Re.MatchString(g.ComposeSHA256) {
		return errors.New("composeSha256 не hex64 в нижнем регистре")
	}
	// Грант без послаблений ничего не разрешает; выпущенный такой — ошибка
	// церемонии, а не пустое разрешение.
	if len(g.Allowances) == 0 {
		return errors.New("в гранте нет послаблений")
	}
	if err := composeguard.ValidateAllowances(g.Allowances); err != nil {
		return fmt.Errorf("грант: %w", err)
	}
	return nil
}

// signedByRoot — корень, которым подписан конверт, или nil.
func signedByRoot(env signenv.Parsed, roots []ed25519.PublicKey) ed25519.PublicKey {
	for _, root := range roots {
		if env.Verify(root) {
			return root
		}
	}
	return nil
}
