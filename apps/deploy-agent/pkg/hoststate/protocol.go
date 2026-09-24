// Package hoststate — подписанное желаемое состояние хоста (ADR-0092), его
// гранты и выбор версии протокола агента (ADR-0093).
//
// Здесь один код формата на обе стороны: подписант выпускает пакет теми же
// функциями, которыми агент его проверяет. Две реализации одного формата
// расходятся молча, и расхождение видно только отказом на хосте клиента.
package hoststate

import (
	"strconv"
	"strings"
)

const (
	// EnvelopeDSSE — обёртка подписи, которую понимает этот код.
	EnvelopeDSSE = "dsse-ed25519/1"
	// ContentV0 — нынешнее желаемое состояние без значений секретов.
	ContentV0 = "host-state/0"

	// Корень подписывает два вида документов, поэтому тип входит в подпись
	// (PAE): грант не выдать за сертификат и наоборот.
	PayloadTypeCert  = "application/vnd.scopework.signer-cert+json"
	PayloadTypeGrant = "application/vnd.scopework.template-grant+json"

	payloadTypeHostStatePrefix = "application/vnd.scopework.host-state+json;v="
	contentFamily              = "host-state"
)

// PayloadTypeHostStateV0 — payloadType конверта с ContentV0.
var PayloadTypeHostStateV0, _ = PayloadTypeFor(ContentV0)

// Protocol — объявление: какие версии содержимого агент исполняет и какие
// обёртки проверяет. Им же платформа описывает, что поддерживает сама.
type Protocol struct {
	Content   []string `json:"content"`
	Envelopes []string `json:"envelopes"`
}

// Choice — выбранные версии; пустая строка — пересечения нет.
type Choice struct {
	Envelope string `json:"envelope"`
	Content  string `json:"content"`
}

// AgentProtocol — что объявляет агент этой сборки. Без корней обёрток нет:
// пустой список, а не null — платформа отличает «не проверяю» от «не
// объявил». Функцией, а не переменной: срез в глобальной переменной можно
// поправить снаружи, и агент объявил бы то, чего не проверяет.
func AgentProtocol(withEnvelopes bool) Protocol {
	envelopes := []string{}
	if withEnvelopes {
		envelopes = []string{EnvelopeDSSE}
	}
	return Protocol{Content: []string{ContentV0}, Envelopes: envelopes}
}

// Negotiate выбирает наибольшие общие версии (ADR-0093, решение 3).
//
// declared == nil — агент без объявления, legacy. Он получает прежний
// неподписанный host-state/0 и ничего больше; если платформа host-state/0 уже
// не поддерживает, Choice пустой, и отвечать такому агенту нужно не 2xx:
// пустое 2xx он применил бы как «снять всё».
func Negotiate(declared *Protocol, platform Protocol) (choice Choice, legacy bool) {
	if declared == nil {
		for _, c := range platform.Content {
			if c == ContentV0 {
				return Choice{Content: ContentV0}, true
			}
		}
		return Choice{}, true
	}
	return Choice{
		Envelope: highestCommon(declared.Envelopes, platform.Envelopes),
		Content:  highestCommon(declared.Content, platform.Content),
	}, false
}

// PayloadTypeFor — payloadType конверта для версии содержимого host-state/N.
func PayloadTypeFor(content string) (string, bool) {
	family, n, ok := parseVersion(content)
	if !ok || family != contentFamily {
		return "", false
	}
	return payloadTypeHostStatePrefix + strconv.Itoa(n), true
}

// highestCommon — наибольшая по числу версия, объявленная обеими сторонами.
// При равном числе у разных семейств побеждает меньшая строка: выбор обязан
// быть одинаковым в Go и TypeScript, а не зависеть от порядка в списке.
func highestCommon(a, b []string) string {
	inB := make(map[string]bool, len(b))
	for _, v := range b {
		inB[v] = true
	}
	best, bestN := "", -1
	for _, v := range a {
		_, n, ok := parseVersion(v)
		if !ok || !inB[v] {
			continue
		}
		if n > bestN || (n == bestN && v < best) {
			best, bestN = v, n
		}
	}
	return best
}

// parseVersion разбирает «семейство/N». N — десятичное без знака и без
// ведущих нулей: «/01» и «/1» не должны оказаться двумя разными версиями с
// одним номером.
func parseVersion(v string) (family string, n int, ok bool) {
	i := strings.LastIndexByte(v, '/')
	if i <= 0 || i == len(v)-1 {
		return "", 0, false
	}
	digits := v[i+1:]
	if len(digits) > 1 && digits[0] == '0' {
		return "", 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return "", 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return "", 0, false
	}
	return v[:i], n, true
}
