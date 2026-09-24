package agent

import (
	"testing"
	"time"
)

func sampleCred() RegistryCredential {
	return RegistryCredential{Registry: "ghcr.io", Username: "octocat", Token: "ghp_abc"}
}

// Решение «входить или нет» повторяет логику needsApply: без отметки — входим,
// при смене данных — входим, после недавней неудачи — ждём паузу.
func TestNeedsRegistryLogin(t *testing.T) {
	now := time.Now()
	cred := sampleCred()
	hash := registryCredHash(cred)

	cases := []struct {
		name  string
		rec   RegistryLoginRecord
		found bool
		want  bool
	}{
		{"нет отметки", RegistryLoginRecord{}, false, true},
		{"данные сменились", RegistryLoginRecord{CredHash: "другой", Status: "ok"}, true, true},
		{"уже вошли", RegistryLoginRecord{CredHash: hash, Status: "ok"}, true, false},
		{
			"недавняя неудача",
			RegistryLoginRecord{CredHash: hash, Status: "failed", LastAttempt: now.Add(-time.Minute)},
			true,
			false,
		},
		{
			"неудача, пауза прошла",
			RegistryLoginRecord{CredHash: hash, Status: "failed", LastAttempt: now.Add(-time.Hour)},
			true,
			true,
		},
	}

	for _, tc := range cases {
		got, reason := needsRegistryLogin(tc.rec, tc.found, hash, now)
		if got != tc.want {
			t.Errorf("%s: получено %v (%s), ожидалось %v", tc.name, got, reason, tc.want)
		}
	}
}

// Смена любого поля учётных данных обязана менять отпечаток: иначе ротация
// токена не приводила бы к повторному входу.
func TestRegistryCredHashChanges(t *testing.T) {
	base := sampleCred()

	variants := []RegistryCredential{
		{Registry: "docker.io", Username: base.Username, Token: base.Token},
		{Registry: base.Registry, Username: "other", Token: base.Token},
		{Registry: base.Registry, Username: base.Username, Token: "rotated"},
	}
	for _, v := range variants {
		if registryCredHash(v) == registryCredHash(base) {
			t.Errorf("отпечаток не изменился для %+v", v)
		}
	}

	// А склейка полей не должна давать коллизий вида ("ab","c") == ("a","bc").
	a := RegistryCredential{Registry: "r", Username: "ab", Token: "c"}
	b := RegistryCredential{Registry: "r", Username: "a", Token: "bc"}
	if registryCredHash(a) == registryCredHash(b) {
		t.Error("коллизия отпечатка при сдвиге границы полей")
	}
}

// Docker Hub хранится как docker.io, но в docker login уходит БЕЗ аргумента
// сервера: ключ учётных данных Hub в конфиге docker — служебный адрес
// index.docker.io, и явный `docker login docker.io` положил бы запись не туда.
func TestRegistryLoginArgs(t *testing.T) {
	got := registryLoginArgs(RegistryCredential{Registry: "docker.io", Username: "u"})
	want := []string{"login", "-u", "u", "--password-stdin"}
	if len(got) != len(want) {
		t.Fatalf("docker.io: получено %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("docker.io: получено %v, ожидалось %v", got, want)
		}
	}

	got = registryLoginArgs(RegistryCredential{Registry: "ghcr.io", Username: "u"})
	if len(got) != 5 || got[1] != "ghcr.io" {
		t.Fatalf("ghcr.io: сервер не попал в аргументы: %v", got)
	}
}

// Агент живёт на чужой машине и не доверяет входу второй раз: мусор с сервера
// не должен попасть в аргументы docker и в stdin.
func TestValidateRegistryCredential(t *testing.T) {
	bad := []RegistryCredential{
		{Registry: "", Username: "u", Token: "t"},
		{Registry: "-flag.example.com", Username: "u", Token: "t"},
		{Registry: "GHCR.io", Username: "u", Token: "t"},
		{Registry: "ghcr.io/path", Username: "u", Token: "t"},
		{Registry: "ghcr.io", Username: "", Token: "t"},
		{Registry: "ghcr.io", Username: "with space", Token: "t"},
		{Registry: "ghcr.io", Username: "-u", Token: "t"},
		{Registry: "ghcr.io", Username: "u", Token: ""},
		{Registry: "ghcr.io", Username: "u", Token: "a\nb"},
		{Registry: "ghcr.io", Username: "u", Token: "a\x00b"},
		// Эндпоинт метаданных облака: реестром не бывает, токены роли отдаёт.
		{Registry: "169.254.169.254", Username: "u", Token: "t"},
		{Registry: "169.254.169.254:80", Username: "u", Token: "t"},
		{Registry: "metadata.google.internal", Username: "u", Token: "t"},
	}
	for _, c := range bad {
		if err := validateRegistryCredential(c); err == nil {
			t.Errorf("принят мусор: %+v", c)
		}
	}

	good := []RegistryCredential{
		{Registry: "docker.io", Username: "user1", Token: "dckr_pat_x"},
		{Registry: "registry.example.com:5000", Username: "gitlab+deploy-token-1", Token: "t"},
		// Самохостовый реестр во внутренней сети — законный сценарий, приватные
		// диапазоны не блокируются.
		{Registry: "10.0.0.5:5000", Username: "u", Token: "t"},
	}
	for _, c := range good {
		if err := validateRegistryCredential(c); err != nil {
			t.Errorf("отвергнут валидный вход %+v: %v", c, err)
		}
	}
}

// Отметки переживают перезапуск агента: без этого каждый рестарт приводил бы
// к повторному docker login по всем реестрам.
func TestRegistryLoginStateRoundTrip(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}

	state := RegistryLoginState{Registries: map[string]RegistryLoginRecord{
		"ghcr.io": {CredHash: "h", Status: "ok", LastAttempt: time.Now().Truncate(time.Second)},
	}}
	if err := SaveRegistryLogins(p, state); err != nil {
		t.Fatalf("сохранение: %v", err)
	}

	loaded := LoadRegistryLogins(p)
	rec, ok := loaded.Registries["ghcr.io"]
	if !ok || rec.CredHash != "h" || rec.Status != "ok" {
		t.Fatalf("после перезагрузки получено %+v", loaded)
	}
}

// Повреждённый файл отметок — не повод падать: худшее последствие — один
// лишний вход в реестры.
func TestLoadRegistryLoginsCorrupted(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	if err := writeFileAtomic(registryLoginsPath(p), []byte("{мусор"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := LoadRegistryLogins(p)
	if state.Registries == nil {
		t.Fatal("после повреждённого файла карта должна быть пустой, а не nil")
	}
}
