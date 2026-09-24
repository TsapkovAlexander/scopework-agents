package hoststate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// SecretValuesMatch — множество ключей значений ровно равно подписанному
// набору ссылок (ADR-0092, решение 10). Значения едут вне конверта, и лишний
// ключ был бы секретом, которого подписант не видел, а недостающий — стеком,
// поднятым без секрета.
func SecretValuesMatch(refs []string, values map[string]string) bool {
	if len(refs) != len(values) {
		return false
	}
	for _, r := range refs {
		if _, ok := values[r]; !ok {
			return false
		}
	}
	return true
}

// AssembleStateV0 подставляет значения секретов в состояние host-state/0.
//
// Секретная переменная кладётся поверх открытой с тем же именем — так же
// собирает env web (toDesiredApp), и одинаковое состояние не должно давать
// разный стек в зависимости от того, подписан ли ответ. Ссылка, которой не на
// что указать (нет приложения, два приложения с одним slug), — ошибка: пакет
// нельзя применить частично.
func AssembleStateV0(state json.RawMessage, refs []string, values map[string]string) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(state))
	// Числа как есть: partSizeBytes и порты не должны пройти через float64.
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil || root == nil {
		return nil, errors.New("state не JSON-объект")
	}

	for _, raw := range refs {
		ref, ok := parseSecretRef(raw)
		if !ok {
			return nil, fmt.Errorf("ссылка %q не по грамматике", raw)
		}
		value, ok := values[raw]
		if !ok {
			return nil, fmt.Errorf("нет значения для %q", raw)
		}
		switch ref.kind {
		case "env", "gitKey", "gitToken":
			app, err := uniqueByField(root, "apps", "slug", ref.slug)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", raw, err)
			}
			if ref.kind != "env" {
				app[ref.kind] = value
				continue
			}
			env, _ := app["env"].(map[string]any)
			if env == nil {
				if app["env"] != nil {
					return nil, fmt.Errorf("%s: env приложения не объект", raw)
				}
				env = map[string]any{}
				app["env"] = env
			}
			env[ref.name] = value
		case "registryToken":
			reg, err := uniqueByField(root, "registries", "registry", ref.registry)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", raw, err)
			}
			reg["token"] = value
		case "objectStorage":
			storage, ok := root["objectStorage"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: в состоянии нет objectStorage", raw)
			}
			storage["secretAccessKey"] = value
		}
	}
	return marshalNoEscape(root)
}

// uniqueByField — единственный элемент списка с заданным значением поля.
func uniqueByField(root map[string]any, list, field, value string) (map[string]any, error) {
	items, _ := root[list].([]any)
	var found map[string]any
	for _, it := range items {
		obj, ok := it.(map[string]any)
		if !ok || obj[field] != value {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("в %s два элемента с %s=%q", list, field, value)
		}
		found = obj
	}
	if found == nil {
		return nil, fmt.Errorf("в %s нет элемента с %s=%q", list, field, value)
	}
	return found, nil
}

// marshalNoEscape — JSON без экранирования <, > и &: в compose и env они
// встречаются, и & вместо & в подписанных байтах только мешает читать
// пакет глазами при разборе отказа.
func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
