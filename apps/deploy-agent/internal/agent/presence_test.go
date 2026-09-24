package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// Список развёрнутого — основание, по которому сервер завершает удаление
// приложения. Ошибка здесь означает либо вечное «удаляется», либо удаление
// записи о стеке, который на самом деле продолжает работать.
func TestPresentSlugs(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}

	// Первый запуск: каталога приложений ещё нет — на хосте действительно
	// ничего не разворачивали. Ответ обязан быть пустым СРЕЗОМ, а не nil:
	// в JSON должно уехать [], а не null.
	got := PresentSlugs(p)
	if got == nil || len(got) != 0 {
		t.Fatalf("на чистом хосте ожидался пустой срез, получено %#v", got)
	}

	appsDir := filepath.Join(p.WorkDir, "apps")
	for _, slug := range []string{"zeta", "alpha", "mid"} {
		if err := os.MkdirAll(filepath.Join(appsDir, slug), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// Мусор рядом: файл и каталог с недопустимым именем в отчёт не идут.
	if err := os.WriteFile(filepath.Join(appsDir, "note.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(appsDir, "../escape-me"), 0o750); err != nil {
		t.Fatal(err)
	}

	got = PresentSlugs(p)
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("получено %v, ожидалось %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("порядок не зафиксирован: получено %v, ожидалось %v", got, want)
		}
	}
}

// Список строится по файловой системе, а НЕ по applied.json.
//
// Потеря или порча отметок не должна выглядеть как «на хосте ничего нет»:
// сервер по такому ответу удалил бы приложения в статусе deleting, оставив их
// работать на хосте — ровно тот осиротевший стек, ради которого удаление и
// сделали двухфазным.
func TestPresentSlugsIgnoresAppliedState(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}

	if err := os.MkdirAll(filepath.Join(p.WorkDir, "apps", "backend"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Отметок нет вовсе — стек всё равно развёрнут.
	got := PresentSlugs(p)
	if len(got) != 1 || got[0] != "backend" {
		t.Fatalf("развёрнутое приложение выпало из списка: %v", got)
	}

	// Повреждённые отметки — тот же результат.
	if err := writeFileAtomic(appliedPath(p), []byte("{мусор"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := PresentSlugs(p); len(got) != 1 || got[0] != "backend" {
		t.Fatalf("повреждённые отметки повлияли на список: %v", got)
	}
}
