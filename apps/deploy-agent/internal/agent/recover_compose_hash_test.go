package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Восстановление не поднимает файл, изменившийся после выката (задача С1.6).
//
// Guard проверяет описание стека ПЕРЕД выкатом — и на тот момент оно чистое.
// Восстановление же поднимает то, что лежит на диске СЕЙЧАС. Если файл успели
// переписать (bind своего каталога закрыт, но остаются ошибки в других
// запретах и чужой доступ к хосту), падение сервиса превращается в подъём
// подменённого стека. Здесь проверяется второй рубеж: сверка с хешом, который
// записал выкат.
func TestRecoverRefusesChangedCompose(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	app := DesiredApp{Slug: "demo", Desired: "running"}

	dir := p.appDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Выкат записал этот текст и запомнил его хеш.
	const applied = "services:\n  app:\n    image: nginx\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(applied), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		app.Slug: {ComposeSha256: sha256Hex(applied)},
	}}); err != nil {
		t.Fatal(err)
	}

	// Контейнер переписал файл: добавил себе привилегии.
	const tampered = "services:\n  app:\n    image: nginx\n    privileged: true\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(tampered), 0o640); err != nil {
		t.Fatal(err)
	}

	err := recoverApp(context.Background(), p, app)
	if err == nil {
		t.Fatal("восстановление подняло подменённый файл")
	}
	if !strings.Contains(err.Error(), "изменилось после выката") {
		t.Fatalf("причина отказа не названа: %v", err)
	}
}

// Обратная сторона: неизменившийся файл восстановление не блокирует. Проверяем
// именно то, что до запуска docker дело доходит — сам запуск здесь не нужен.
func TestRecoverPassesHashCheckForUnchangedCompose(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	app := DesiredApp{Slug: "demo", Desired: "running"}

	dir := p.appDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const applied = "services:\n  app:\n    image: nginx\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(applied), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		app.Slug: {ComposeSha256: sha256Hex(applied)},
	}}); err != nil {
		t.Fatal(err)
	}

	err := recoverApp(context.Background(), p, app)
	// Docker в тестовой среде до стека не дойдёт, и это нормально: важно, что
	// отказ пришёл НЕ от сверки хеша.
	if err != nil && strings.Contains(err.Error(), "изменилось после выката") {
		t.Fatalf("неизменившийся файл объявлен подменённым: %v", err)
	}
}

// Приложение, применённое версией агента без записи хеша, восстанавливается
// как раньше: молчание честнее, чем остановка работающего восстановления.
func TestRecoverWithoutRecordedHashStillRuns(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	app := DesiredApp{Slug: "demo", Desired: "running"}
	dir := p.appDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := recoverApp(context.Background(), p, app)
	if err != nil && strings.Contains(err.Error(), "изменилось после выката") {
		t.Fatalf("без записанного хеша восстановление остановлено: %v", err)
	}
}
