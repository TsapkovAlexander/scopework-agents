package agent

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Поток docker events — только триггер внеочередной выборки (ADR-0091,
// решение 5): классифицирует сверка, поток лишь будит её.

func TestWorkloadStreamLifecycleActions(t *testing.T) {
	cases := map[string]bool{
		`{"Type":"container","Action":"start","Actor":{"ID":"x"}}`:                       true,
		`{"Type":"container","Action":"die","Actor":{"Attributes":{"exitCode":"1"}}}`:    true,
		`{"Type":"container","Action":"health_status: unhealthy"}`:                       true,
		`{"Type":"container","Action":"oom"}`:                                            true,
		`{"Type":"container","Action":"destroy"}`:                                        true,
		`{"status":"restart","id":"x","from":"nginx"}`:                                   true, // прежний формат
		`{"Type":"container","Action":"exec_create: pg_isready -U postgres"}`:            false,
		`{"Type":"container","Action":"exec_start: pg_isready -U postgres"}`:             false,
		`{"Type":"container","Action":"exec_die"}`:                                       false,
		`{"Type":"container","Action":"attach"}`:                                         false,
		`{"Type":"image","Action":"pull"}`:                                               false,
		`not json`:                                                                       false,
		`{"Type":"container","Action":"start","status":"exec_start: sh"}`:                true,
		`{"Type":"container","Action":"rename","Actor":{"Attributes":{"oldName":"/a"}}}`: true,
	}
	for line, want := range cases {
		if got := workloadLifecycleEvent([]byte(line)); got != want {
			t.Errorf("%s: %v, ожидалось %v", line, got, want)
		}
	}
}

// Каждое действие жизненного цикла будит выборку; проверки здоровья
// (exec_*) — нет: иначе каждая давала бы три выборки (ADR-0061, факт 2).
func TestWorkloadStreamSignalsLifecycleOnly(t *testing.T) {
	d := installWorkloadDocker(t)
	d.write("events.out", `{"Type":"container","Action":"exec_create: curl -f localhost"}`+"\n"+
		`{"Type":"container","Action":"exec_start: curl -f localhost"}`+"\n"+
		`{"Type":"container","Action":"exec_die"}`+"\n"+
		`{"Type":"container","Action":"die"}`+"\n"+
		`{"Type":"container","Action":"start"}`+"\n")
	d.write("events.modes", "exit\n")

	var started, events atomic.Int32
	err := workloadWatchEvents(context.Background(), func() { started.Add(1) }, func() { events.Add(1) })
	if err == nil {
		t.Fatal("обрыв потока не назван ошибкой")
	}
	if started.Load() != 1 || events.Load() != 2 {
		t.Fatalf("запусков %d, событий %d; ожидалось 1 и 2", started.Load(), events.Load())
	}
	if d.count("events --filter type=container --format {{json .}}") != 1 {
		t.Fatalf("вызовы %q", d.calls())
	}
}

// Остановка убивает и дожидается `docker events`: осиротевший поток перед
// exec самообновления жил бы рядом со следующим, и так на каждом обновлении.
func TestWorkloadStreamCancelReapsChild(t *testing.T) {
	d := installWorkloadDocker(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- workloadWatchEvents(ctx, nil, func() {}) }()

	pid := workloadWaitPid(t, d, 1)
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("поток не запущен: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("поток не остановился по контексту")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("docker events (pid %d) пережил остановку: %v", pid, err)
	}
}

// workloadWaitPid ждёт n-го запуска подставного `docker events` и отдаёт его pid.
func workloadWaitPid(t *testing.T, d *workloadDockerStub, n int) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pids := d.eventsPids(); len(pids) >= n {
			return pids[n-1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("docker events не запущен %d-й раз; вызовы %q", n, strings.Join(d.calls(), "; "))
	return 0
}
