package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// Корни подписи желаемого состояния (ADR-0092, ADR-0093, решение 2).
//
// Проверять ли подпись состояния — свойство бинаря, а не режим в базе:
// значение подставляется при сборке ключом компоновщика -X с именем
// tracedocs.ru/deploy-agent/internal/agent.trustedStateRootsRaw, и выключить
// проверку с платформы нечем.
//
// Формат — base64 std с паддингом от сырых 32 байт Ed25519, через запятую, без
// пробелов; порядок не важен. Источник — apps/deploy-agent/trust/state/*.pub,
// склейку делает сборка штаба К. Имя переменной — контракт с ней: компоновщик
// молча пропускает -X несуществующего символа, и переименование дало бы агента
// «без корней» без единой ошибки сборки.
//
// ПУСТО — корней нет: агент объявляет `envelopes: []` и применяет
// неподписанное, как раньше.
//
// ХОТЬ ОДИН ЭЛЕМЕНТ НЕ ЧИТАЕТСЯ — не применяется никакое состояние. В
// release_trust.go битый ключ пропускается; здесь нет: ошибка выпуска не должна
// тихо стать «проверок нет» или проверкой меньшим набором, чем задумано.
var trustedStateRootsRaw = ""

// parseStateRoots разбирает значение сборки. Пусто — (nil, nil).
func parseStateRoots(raw string) ([]ed25519.PublicKey, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	roots := make([]ed25519.PublicKey, 0, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("корень %d: пустой элемент списка", i+1)
		}
		key, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("корень %d: не base64", i+1)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("корень %d: %d байт, ожидалось %d", i+1, len(key), ed25519.PublicKeySize)
		}
		roots = append(roots, ed25519.PublicKey(key))
	}
	return roots, nil
}

// StateRootsStatus — корни сборки и их исправность. Три состояния различаются
// так: (nil, nil) — корней нет; (корни, nil) — проверка включена; (nil,
// ошибка) — корни вшиты, но не читаются, и состояние не применяется вовсе.
func StateRootsStatus() ([]ed25519.PublicKey, error) {
	roots, err := parseStateRoots(trustedStateRootsRaw)
	if err != nil {
		return nil, fmt.Errorf("корни подписи состояния в сборке нечитаемы: %w", err)
	}
	return roots, nil
}

// TrustedStateRoots — корни для доклада; nil и при пустом, и при битом
// значении. Отличить одно от другого — StateRootsStatus.
func TrustedStateRoots() []ed25519.PublicKey {
	roots, _ := StateRootsStatus()
	return roots
}

// stateRootsDeclared — вшито ли в сборку хоть что-то, пусть и битое. Такой
// агент докладывает итог проверки каждым тактом: молчание битых корней
// выглядело бы на платформе как агент без проверки.
func stateRootsDeclared() bool { return trustedStateRootsRaw != "" }

// Подмена значения сборки на время теста, в том числе для тестов пакета main.
// Возвращает функцию возврата прежнего значения. Имя функции в комментарии не
// повторяется: гейт приёмки ждёт его вне тестов ровно в одной строке.
//
// В рабочем файле, а не в export_test.go, потому что её зовёт
// main_signing_test.go: экспорт из _test.go виден только тестам этого же
// пакета, а приём пакета в main проверяется с настоящими корнями сборки.
func SetTrustedStateRootsForTest(raw string) (restore func()) {
	// Через указатель: гейт приёмки ищет присваивания этой переменной вне
	// тестов, и единственным обязано остаться объявление выше.
	value := &trustedStateRootsRaw
	prev := *value
	*value = raw
	return func() { *value = prev }
}
