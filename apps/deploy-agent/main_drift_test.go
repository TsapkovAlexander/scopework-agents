package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// installTickFakes кладёт в PATH поддельные docker и ss: такт целиком трогает
// хост, а проверяется здесь только порядок сверки и перезаписи.
//
// docker отвечает на два вопроса выката — состав сервисов и состояние
// контейнеров, — иначе применение ждало бы здоровья до срока. ss пуст: порты
// 80/443 на машине прогона может держать что угодно.
func installTickFakes(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	docker := "#!/bin/sh\n" +
		"cat >/dev/null\n" +
		`case " $* " in` + "\n" +
		`  *" config "*"--services "*) printf 'app\n';;` + "\n" +
		`  *" ps --all "*) printf 'app\trunning\t\t0\n';;` + "\n" +
		"esac\n" +
		"exit 0\n"
	for name, script := range map[string]string{"docker": docker, "ss": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Сверка дрейфа в такте идёт ДО применения (ADR-0078): ручная правка
// Caddyfile между тактами уезжает сигналом с хешем правки, хотя этот же такт
// файл перезаписывает. Сверка после applyDesired видела бы уже свою запись и
// молчала бы.
func TestTickObservesDriftBeforeRewrite(t *testing.T) {
	installTickFakes(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	client := agent.NewClient(srv.URL, "test")
	id := testIdentity(t)
	gate := agent.NewReportGate()
	queue := agent.LoadReportQueue(paths)
	var proxyError atomic.Pointer[string]
	var heartbeat atomic.Pointer[agent.HeartbeatResponse]
	state := agent.DesiredState{Apps: []agent.DesiredApp{{
		Slug:         "shop-front",
		Desired:      "present",
		ReleaseID:    "release-1",
		Compose:      "services:\n  app:\n    image: nginx\n",
		Domain:       "shop.example.com",
		InternalPort: 80,
		ApplySpec:    agent.ApplySpec{StableChecks: 1},
	}}}

	runTick := func() *agent.ReportSection {
		t.Helper()
		report, _ := tick(t.Context(), client, id, paths, agent.ProxyOptions{}, state,
			true, false, &proxyError, &heartbeat, gate, queue, false)
		if report.Report == nil {
			t.Fatal("такт без секции report")
		}
		return report.Report
	}

	runTick()
	caddyfile := filepath.Join(paths.WorkDir, "proxy", "conf", "Caddyfile")
	written, err := os.ReadFile(caddyfile)
	if err != nil {
		t.Fatalf("первый такт не записал Caddyfile: %v", err)
	}

	edited := string(written) + "\nhandmade.example.com {\n\trespond 200\n}\n"
	if err := os.WriteFile(caddyfile, []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	section := runTick()
	if got := hexSha256Bytes(t, caddyfile); got != hexSha256(string(written)) {
		t.Fatal("такт не перезаписал правленый Caddyfile — проверять порядок не на чем")
	}
	var found *agent.DriftItem
	for i := range section.Drift {
		if section.Drift[i].Object == "caddyfile" && section.Drift[i].Seq == section.Seq {
			found = &section.Drift[i]
		}
	}
	if found == nil {
		t.Fatalf("правка Caddyfile не дала сигнала этого такта — сверка шла после перезаписи: %+v", section.Drift)
	}
	if found.Status != "mismatch" || found.Disposition != "foreign" ||
		found.DiskSha != hexSha256(edited) || found.ExpectedSha != hexSha256(string(written)) {
		t.Fatalf("сигнал правки Caddyfile: %+v", *found)
	}
}

func hexSha256Bytes(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return hexSha256(string(raw))
}
