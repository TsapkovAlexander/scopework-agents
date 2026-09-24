package composeguard

import (
	"strings"
	"testing"
)

func secretVars(t *testing.T, normalized string, secrets ...string) []Violation {
	t.Helper()
	v, err := CheckSecretVars([]byte(normalized), secrets)
	if err != nil {
		t.Fatalf("разбор не удался: %v", err)
	}
	return v
}

// Секрет в environment — ровно то, ради чего секреты существуют.
func TestSecretVarsAllowsEnvironmentAndCommand(t *testing.T) {
	v := secretVars(t, `{"services":{"app":{
		"image":"node:22","environment":{"DB_URL":"postgres://u:${DB_PASSWORD}@db/app"},
		"command":["run","$DB_PASSWORD"],"healthcheck":{"test":["CMD","${DB_PASSWORD}"]}
	}}}`, "DB_PASSWORD")
	if len(v) != 0 {
		t.Fatalf("законное использование секрета отклонено: %v", v)
	}
}

// Подменённое значение секрета не должно становиться образом, томом или правом
// ядра (ADR-0082, решение 6): web пишет значения, и взломанный web иначе выбрал
// бы, что поднять на хосте, не трогая подписанного текста.
func TestSecretVarsBlocksDangerousServiceFields(t *testing.T) {
	cases := map[string]string{
		"image":                 `"image":"${S}"`,
		"image короткой формой": `"image":"registry/$S:1"`,
		"image со значением по умолчанию": `"image":"${S:-nginx}"`,
		"build.context":       `"build":{"context":"${S}"}`,
		"build.args":          `"build":{"context":".","args":{"A":"$S"}}`,
		"volumes":             `"volumes":[{"type":"bind","source":"${S}","target":"/x"}]`,
		"volumes_from":        `"volumes_from":["${S}"]`,
		"devices":             `"devices":[{"source":"$S","target":"/dev/x"}]`,
		"device_cgroup_rules": `"device_cgroup_rules":["${S}"]`,
		"privileged":          `"privileged":"${S}"`,
		"cap_add":             `"cap_add":["${S}"]`,
		"security_opt":        `"security_opt":["$S"]`,
		"network_mode":        `"network_mode":"${S}"`,
		"pid":                 `"pid":"${S}"`,
		"ipc":                 `"ipc":"${S}"`,
		"userns_mode":         `"userns_mode":"${S}"`,
		"cgroup_parent":       `"cgroup_parent":"${S}"`,
		"cgroup":              `"cgroup":"${S}"`,
		"uts":                 `"uts":"${S}"`,
		"ports":               `"ports":[{"published":"${S}","target":80}]`,
		"secrets":             `"secrets":[{"source":"${S}"}]`,
		"configs":             `"configs":[{"source":"${S}"}]`,
		"вложенная подстановка": `"image":"${OTHER:-${S}}"`,
	}
	for name, field := range cases {
		v := secretVars(t, `{"services":{"app":{`+field+`}}}`, "S")
		if len(v) == 0 {
			t.Errorf("%s: секрет в опасном поле пропущен", name)
			continue
		}
		if !strings.Contains(v[0].String(), "app") || !strings.Contains(v[0].Reason, "S") {
			t.Errorf("%s: нарушение не называет сервис и переменную: %v", name, v[0])
		}
	}
}

// Верхний уровень: определения томов, сетей, секретов и конфигов ведут на
// хост так же, как поля сервиса.
func TestSecretVarsBlocksDangerousTopLevel(t *testing.T) {
	cases := map[string]string{
		"volumes":  `"volumes":{"d":{"driver_opts":{"device":"${S}"}}}`,
		"networks": `"networks":{"n":{"external":true,"name":"${S}"}}`,
		"secrets":  `"secrets":{"x":{"file":"${S}"}}`,
		"configs":  `"configs":{"x":{"file":"$S"}}`,
	}
	for name, field := range cases {
		if v := secretVars(t, `{"services":{"app":{"image":"x"}},`+field+`}`, "S"); len(v) == 0 {
			t.Errorf("%s: секрет на верхнем уровне пропущен", name)
		}
	}
}

// Переменная с похожим именем секретом не является, $$ — экранированный
// доллар, а не подстановка. Ложный отказ здесь стоил бы подписи обычного стека.
func TestSecretVarsIgnoresNonSecretsAndEscapes(t *testing.T) {
	v := secretVars(t, `{"services":{"app":{
		"image":"nginx:${TAG}","volumes":[{"type":"volume","source":"$$S","target":"/x"}],
		"cap_add":["${S_OTHER}","$SX"]
	}}}`, "S")
	if len(v) != 0 {
		t.Fatalf("ложный отказ: %v", v)
	}
}

// Ключ объекта тоже текст из compose: подстановка в имени тома или сети
// ведёт туда же, куда и в значении.
func TestSecretVarsChecksObjectKeys(t *testing.T) {
	v := secretVars(t, `{"services":{"app":{"image":"x"}},"volumes":{"${S}":{}}}`, "S")
	if len(v) == 0 {
		t.Fatal("секрет в имени тома пропущен")
	}
}

func TestSecretVarsRejectsUnreadableModel(t *testing.T) {
	if _, err := CheckSecretVars([]byte(`не json`), []string{"S"}); err == nil {
		t.Fatal("нечитаемый вывод принят")
	}
	if v := secretVars(t, `{"services":{"app":{"image":"${S}"}}}`); len(v) != 0 {
		t.Fatalf("без секретов нечего запрещать: %v", v)
	}
}

// Поле, которое guard разбирает отдельным правилом, опасно и с подставленным
// секретом. Перечни расходятся молча — новое правило guard без строки здесь
// оставило бы поле открытым для подменённого значения.
func TestSecretVarsFieldsCoverCheckedKeys(t *testing.T) {
	want := map[string]bool{"image": true}
	for key := range checkedServiceKeys {
		want[key] = true
	}
	for key := range want {
		if !secretDangerousServiceFields[key] {
			t.Errorf("%s: guard проверяет поле, а подстановка секрета в него разрешена", key)
		}
	}
	for key := range secretDangerousServiceFields {
		if !want[key] {
			t.Errorf("%s: запрещено для секретов, но у guard правила нет — перечень ADR-0082 §6 разошёлся с кодом", key)
		}
	}
}
