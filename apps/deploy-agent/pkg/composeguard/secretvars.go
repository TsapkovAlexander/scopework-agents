package composeguard

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Запрет подстановки секретной переменной в опасные поля (ADR-0082, решение 6).
//
// ЗАЧЕМ. Подпись закрывает имена и набор секретов, но не значения: их пишет
// web, а web вне доверия. Если значение секрета подставляется в image или в
// путь тома, взломанный web выбирает, какой образ поднять и что смонтировать,
// не трогая ни одного подписанного байта. Здесь значение может увести
// приложение в чужую базу, но не может стать образом, томом или правом ядра.
//
// Проверяется модель `docker compose config --no-interpolate`: после
// подстановки ссылка на переменную исчезает, и видно только значение.
//
// ПЕРЕЧЕНЬ ПОЛЕЙ — исходный список ADR-0082 плюс то, что Check разбирает
// отдельным правилом (checkedServiceKeys, и image): поле, опасное само по
// себе, опасно и с подставленным значением. ADR-0082 §6 перечисляет ровно этот
// набор; расширяется он здесь и там одной правкой.
var secretDangerousServiceFields = map[string]bool{
	"image": true, "build": true, "volumes": true, "volumes_from": true,
	"devices": true, "device_cgroup_rules": true, "privileged": true,
	"cap_add": true, "security_opt": true, "network_mode": true, "pid": true,
	"ipc": true, "userns_mode": true, "cgroup_parent": true,
	"cgroup": true, "uts": true, "ports": true, "secrets": true, "configs": true,
}

var secretDangerousTopLevel = map[string]bool{
	"volumes": true, "networks": true, "secrets": true, "configs": true,
}

// CheckSecretVars ищет `${NAME}` и `$NAME` секретных переменных в опасных полях.
func CheckSecretVars(rawModel []byte, secretNames []string) ([]Violation, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rawModel, &top); err != nil {
		return nil, fmt.Errorf("не удалось разобрать нормализованный compose: %w", err)
	}
	var raw struct {
		Services map[string]map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(rawModel, &raw); err != nil {
		return nil, fmt.Errorf("не удалось разобрать сервисы compose: %w", err)
	}
	secret := make(map[string]bool, len(secretNames))
	for _, n := range secretNames {
		secret[n] = true
	}
	if len(secret) == 0 {
		return nil, nil
	}

	var out []Violation
	report := func(who, field string, raw json.RawMessage) error {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("поле %s не разбирается: %w", field, err)
		}
		found := map[string]bool{}
		collectVars(value, func(name string) {
			if secret[name] {
				found[name] = true
			}
		})
		names := make([]string, 0, len(found))
		for n := range found {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, Violation{
				Service: who,
				Reason: field + ": подстановка секретной переменной " + n + " запрещена — " +
					"значение секрета не подписано и не может решать, что и с какими правами поднимается",
			})
		}
		return nil
	}

	for _, name := range sortedKeys(raw.Services) {
		svc := raw.Services[name]
		for _, field := range sortedKeys(svc) {
			if !secretDangerousServiceFields[field] {
				continue
			}
			if err := report(name, field, svc[field]); err != nil {
				return nil, err
			}
		}
	}
	for _, field := range sortedKeys(top) {
		if !secretDangerousTopLevel[field] {
			continue
		}
		if err := report("описание", field, top[field]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// collectVars обходит значение и отдаёт имена всех подстановок, включая
// вложенные в значение по умолчанию: `${A:-${B}}` подставляет B.
func collectVars(value any, emit func(string)) {
	switch v := value.(type) {
	case string:
		scanVars(v, emit)
	case []any:
		for _, item := range v {
			collectVars(item, emit)
		}
	case map[string]any:
		for key, item := range v {
			scanVars(key, emit)
			collectVars(item, emit)
		}
	}
}

// scanVars — разбор подстановок по правилам compose: `$$` — литерал, имя —
// [A-Za-z_][A-Za-z0-9_]*. После имени в `${...}` разбор продолжается с того же
// места, поэтому вложенная подстановка в значении по умолчанию не теряется.
func scanVars(s string, emit func(string)) {
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) {
			continue
		}
		next := s[i+1]
		switch {
		case next == '$':
			i++
		case next == '{':
			if name := varName(s[i+2:]); name != "" {
				emit(name)
				i += 1 + len(name)
			}
		default:
			if name := varName(s[i+1:]); name != "" {
				emit(name)
				i += len(name)
			}
		}
	}
}

func varName(s string) string {
	end := 0
	for end < len(s) {
		c := s[end]
		isLetter := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !isLetter && (end == 0 || c < '0' || c > '9') {
			break
		}
		end++
	}
	return s[:end]
}

// sortedKeys — порядок нарушений детерминирован: подписант пишет отказ в базу,
// и одинаковый compose обязан давать одинаковый текст.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
