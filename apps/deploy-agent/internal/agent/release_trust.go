package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Доверие к тому, что приезжает с платформы (ADR-0082, задачи С1.2–С1.4).
//
// ЗАЧЕМ. Сегодня агент верит платформе по TLS: сумма бинаря приезжает тем же
// ответом, что и сам бинарь, а желаемое состояние не подписано вовсе. Значит
// тот, кто завладел платформой, получает произвольный код на КАЖДОМ
// подключённом сервере. TLS отвечает на вопрос «с тем ли сервером я говорю», а
// не «то ли мне прислали».
//
// КЛЮЧ ВШИТ В АГЕНТ, А НЕ ПРИХОДИТ С ПЛАТФОРМЫ. Иначе проверка сводится к
// «платформа сказала, что это она». Значение подставляется при сборке:
//
//	go build -ldflags "-X tracedocs.ru/deploy-agent/internal/agent.trustedKeysRaw=<ключи>"
//
// СПИСОК, А НЕ ОДИН КЛЮЧ. Смена ключа переживается только так: новая пара
// приезжает новой версией агента, некоторое время принимаются обе подписи,
// старый ключ снимается следующей версией. Ключ, потерянный без такого запаса,
// означал бы переустановку агента на каждом сервере руками.
//
// ПУСТОЙ СПИСОК — ПРОВЕРКИ НЕТ. Это состояние на 18.09.2026: ключ ещё не
// выпущен (его делает владелец офлайн, ADR-0082). Агент в этом состоянии ведёт
// себя как раньше и ГОВОРИТ об этом в отчёте — молчаливое «проверок нет» и было
// тем, из-за чего задача попала в план.
var trustedKeysRaw = ""

// TrustedReleaseKeys — годные ключи из сборочной константы: для отпечатков и
// счёта. Годятся ли ключи для проверки вообще, отвечает ReleaseKeysError.
func TrustedReleaseKeys() []ed25519.PublicKey {
	keys, _ := parseTrustedKeys(trustedKeysRaw)
	return keys
}

// ReleaseKeysError — список ключей в сборке испорчен.
//
// Битый ключ — ошибка выпуска, и самообновление отказывает ЦЕЛИКОМ. Прежде он
// молча пропускался: агент работал на оставшихся ключах так, будто сборка
// исправна, а при единственном битом — вовсе без проверки подписи.
func ReleaseKeysError() error {
	_, err := parseTrustedKeys(trustedKeysRaw)
	return err
}

// parseTrustedKeys — годные ключи и ошибка, если хоть один непустой элемент
// списка — не std-base64 сырых 32 байт. Пустые элементы — не ключи и не порча.
func parseTrustedKeys(list string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	broken := 0
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			broken++
			continue
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	if broken > 0 {
		return out, fmt.Errorf("ключи выпуска в сборке испорчены: негодных %d", broken)
	}
	return out, nil
}

// ReleaseSignatureRequired — обязана ли подпись быть проверена: в сборку
// вшито хоть что-то. Испорченный список — тоже «обязана»: проверка тогда
// отказывает, а не пропускает.
func ReleaseSignatureRequired() bool { return strings.Trim(trustedKeysRaw, " ,\t") != "" }

// VerifyReleaseSignature — проверка подписи над сообщением любым из доверенных
// ключей.
//
// Сообщение собирает вызывающий: для бинаря это его sha256 и версия, для
// манифеста — его канонический вид. Подпись в base64 приезжает заголовком.
func VerifyReleaseSignature(message []byte, signatureB64 string) error {
	keys, err := parseTrustedKeys(trustedKeysRaw)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		// Ключей нет — проверять нечем. Отказывать здесь значило бы сломать
		// всех работающих агентов в день, когда ключ ещё не выпущен.
		return nil
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("подпись выпуска отсутствует или испорчена")
	}
	for _, key := range keys {
		if ed25519.Verify(key, message, sig) {
			return nil
		}
	}
	return fmt.Errorf("подпись выпуска не проходит проверку доверенными ключами")
}

// ReleaseBinaryMessage — что именно подписывается у бинаря агента.
//
// Версия входит в сообщение вместе с суммой: иначе подпись старого бинаря
// годилась бы для отката, а откат — это способ снять уже поставленную защиту.
func ReleaseBinaryMessage(version, sha256Hex, arch string) []byte {
	return []byte("agent-binary\n" + strings.TrimSpace(version) + "\n" +
		strings.ToLower(strings.TrimSpace(sha256Hex)) + "\n" + strings.TrimSpace(arch))
}

// KeyFingerprint — первые 16 hex sha256 сырых 32 байт ключа. Короче полного
// ключа, чтобы человек мог сверить его глазами с опубликованным, и длиннее,
// чем нужно для случайного совпадения.
func KeyFingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:16]
}

func keyFingerprints(keys []ed25519.PublicKey) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, KeyFingerprint(key))
	}
	return out
}

// TrustReport — поле trust тела такта: каким ключам верит этот агент и какая
// версия у прокси сокета.
//
// Версия прокси отдельно от версии агента: прокси — root-бинарь из
// /usr/local/bin, который самообновление не трогает (ADR-0095, п. 5). Хост,
// получивший агента с режимом наблюдения самообновлением, держит прежний
// прокси до переустановки, и карточка сервера должна это видеть.
//
// stateRoots — отпечатки корней подписи состояния (state_trust.go). Как и
// releaseKeys, всегда массив: пустой — корней нет, а не «поле не прислали».
// Битые корни дают пустой массив; что состояние при этом не применяется,
// платформа видит по итогу проверки подписи в том же такте.
type TrustReport struct {
	ReleaseKeys  []string `json:"releaseKeys"`
	StateRoots   []string `json:"stateRoots"`
	ProxyVersion string   `json:"proxyVersion"`
}

// NewTrustReport — доклад по вшитым ключам. proxyVersion — вывод `version`
// бинаря прокси, пусто, если его нет.
func NewTrustReport(proxyVersion string) TrustReport {
	return TrustReport{
		ReleaseKeys:  keyFingerprints(TrustedReleaseKeys()),
		StateRoots:   keyFingerprints(TrustedStateRoots()),
		ProxyVersion: proxyVersion,
	}
}
