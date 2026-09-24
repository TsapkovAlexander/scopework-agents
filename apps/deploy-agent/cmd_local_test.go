package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Подкоманды для владельца сервера: `journal`, `policy`, `version --trust`.
// Ими человек проверяет агента без платформы, поэтому коды выхода и формат —
// контракт: на них опираются install.sh и сборка выпуска.

func writtenJournal(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.log")
	j := agent.OpenJournal(path, io.Discard, "2.2.0")
	for _, h := range []string{"a", "b", "c"} {
		if _, err := j.Receive(agent.JournalKindHostTask, hexSha256(h), nil, agent.DecisionAccepted, ""); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestJournalVerifyExitCodes(t *testing.T) {
	path := writtenJournal(t)
	var out, errOut bytes.Buffer
	if code := cmdJournal([]string{"verify", "--file=" + path}, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "цепочка цела: записей 4") ||
		!strings.Contains(out.String(), "атрибут только дописывания (chattr +a): ") {
		t.Fatalf("целый журнал: код %d, %q %q", code, out.String(), errOut.String())
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], `"accepted"`, `"refused"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := cmdJournal([]string{"verify", "--file=" + path}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "строка 2") {
		t.Fatalf("правленый журнал: код %d, %q", code, out.String())
	}

	if code := cmdJournal([]string{"verify", "--file=" + filepath.Join(t.TempDir(), "nope")}, &out, &errOut); code != 2 {
		t.Fatalf("нечитаемый журнал: код %d", code)
	}
	if code := cmdJournal([]string{"rotate"}, &out, &errOut); code != 2 {
		t.Fatalf("незнакомая подкоманда: код %d", code)
	}
}

func TestJournalShowCommand(t *testing.T) {
	path := writtenJournal(t)
	var out bytes.Buffer
	if code := cmdJournal([]string{"show", "--since=3", "--file=" + path}, &out, io.Discard); code != 0 {
		t.Fatalf("show: код %d", code)
	}
	if got := strings.Count(out.String(), "\n"); got != 2 || !strings.Contains(out.String(), `"seq":3`) {
		t.Fatalf("show --since=3:\n%s", out.String())
	}
}

func TestPolicyShowCommand(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		code  int
		wants []string
	}{
		{"файла нет", "", 0, []string{"политика не задана"}},
		{"наблюдение с auto без ключа", "version=1\ndeploy_agent_updates=auto\ncommands=inventory\n", 0,
			[]string{"mode=observe", "commands=inventory", "deploy_agent_updates=auto (исполняется как manual", "защищён: нет"}},
		{"негодный файл", "version=1\nmode=Deploy\n", 1,
			[]string{"файл негоден: mode", "mode=observe", "commands=\n", "container_logs=deny"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPolicyFile(t, tc.text)
			var out bytes.Buffer
			if code := cmdPolicy([]string{"show"}, &out, io.Discard); code != tc.code {
				t.Fatalf("код %d, ожидался %d:\n%s", code, tc.code, out.String())
			}
			for _, want := range tc.wants {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("нет %q в выводе:\n%s", want, out.String())
				}
			}
		})
	}
}

// version --trust — ровно три строки: их разбирает install.sh и сверяет
// сборка. Испорченные ключи или корни — причина в stderr и код 1.
func TestVersionTrustOutput(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	r1, _, _ := ed25519.GenerateKey(rand.Reader)
	r2, _, _ := ed25519.GenerateKey(rand.Reader)
	var out, errOut bytes.Buffer
	if code := versionTrust(&out, &errOut, "2.2.0", []ed25519.PublicKey{a, b}, nil, []ed25519.PublicKey{r1, r2}, nil); code != 0 {
		t.Fatalf("код %d", code)
	}
	want := "version=2.2.0\nrelease_keys=" + agent.KeyFingerprint(a) + "," + agent.KeyFingerprint(b) +
		"\nstate_roots=" + agent.KeyFingerprint(r1) + "," + agent.KeyFingerprint(r2) + "\n"
	if out.String() != want {
		t.Fatalf("вывод:\n%q\nожидалось:\n%q", out.String(), want)
	}

	// Корней нет — строка есть, но пустая: install.sh говорит «корней нет», а
	// не молчит, как у сборок без кода проверки состояния.
	out.Reset()
	if code := versionTrust(&out, &errOut, "2.2.0", []ed25519.PublicKey{a}, nil, nil, nil); code != 0 ||
		out.String() != "version=2.2.0\nrelease_keys="+agent.KeyFingerprint(a)+"\nstate_roots=\n" {
		t.Fatalf("без корней: код %d, вывод %q", code, out.String())
	}

	out.Reset()
	if code := versionTrust(&out, &errOut, "2.2.0", []ed25519.PublicKey{a}, errors.New("ключи выпуска в сборке испорчены"), nil, nil); code != 1 ||
		out.Len() != 0 || !strings.Contains(errOut.String(), "испорчены") {
		t.Fatalf("битые ключи: код %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := versionTrust(&out, &errOut, "2.2.0", []ed25519.PublicKey{a}, nil, nil, errors.New("корни подписи состояния в сборке нечитаемы")); code != 1 ||
		out.Len() != 0 || !strings.Contains(errOut.String(), "нечитаемы") {
		t.Fatalf("битые корни: код %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}

	out.Reset()
	if code := cmdVersion(nil, &out, io.Discard); code != 0 || out.String() != Version+"\n" {
		t.Fatalf("простой version: %d %q", code, out.String())
	}
}

func TestAppendOnlyText(t *testing.T) {
	yes, no := true, false
	for value, want := range map[*bool]string{nil: "не определить", &yes: "есть", &no: "нет"} {
		if got := appendOnlyText(value); !strings.HasPrefix(got, want) {
			t.Fatalf("%v → %q", value, got)
		}
	}
}

func TestProxyBinaryVersion(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tracedocs-deploy-agent")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 2.1.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := proxyBinaryPath
	t.Cleanup(func() { proxyBinaryPath = prev })

	proxyBinaryPath = bin
	if got := proxyBinaryVersion(t.Context()); got != "2.1.0" {
		t.Fatalf("версия прокси %q", got)
	}
	proxyBinaryPath = filepath.Join(t.TempDir(), "nope")
	if got := proxyBinaryVersion(t.Context()); got != "" {
		t.Fatalf("без бинаря версия %q", got)
	}
}
