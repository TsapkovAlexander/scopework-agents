package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// Две формы аддона обязаны описывать ОДНО И ТО ЖЕ.
//
// Текстовая идёт в синтетический стек, модельная — в чужой compose. Разъехавшись,
// они дали бы одному клиенту базу с проверкой здоровья и лимитом памяти, а
// другому — без, и заметить это можно было бы только сравнив два хоста.
func TestAddonFormsAgree(t *testing.T) {
	spec := AddonSpec{
		Kind:    "postgres",
		Service: "db",
		Image:   "postgres:17-alpine@sha256:" + strings.Repeat("a", 64),
	}

	text, err := renderAddonServices([]AddonSpec{spec})
	if err != nil {
		t.Fatalf("текстовая форма: %v", err)
	}
	model, volume, err := addonServiceModel(spec)
	if err != nil {
		t.Fatalf("модельная форма: %v", err)
	}

	// Существенное — то, от чего зависит поведение базы у клиента.
	for _, want := range []string{
		spec.Image,
		"POSTGRES_USER", "POSTGRES_DB", "POSTGRES_PASSWORD",
		"pg_isready -U app -d app",
		"no-new-privileges:true",
		volume + ":/var/lib/postgresql/data",
		"512M",
	} {
		if !strings.Contains(text.services, want) {
			t.Errorf("текстовая форма потеряла %q", want)
		}
	}

	blob, err := json.Marshal(model)
	if err != nil {
		t.Fatalf("модель не сериализуется: %v", err)
	}
	for _, want := range []string{
		spec.Image,
		"POSTGRES_USER", "POSTGRES_DB", "POSTGRES_PASSWORD",
		"pg_isready -U app -d app",
		"no-new-privileges:true",
		volume + ":/var/lib/postgresql/data",
		"512M",
	} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("модельная форма потеряла %q", want)
		}
	}

	if volume != addonPostgresVolume || !strings.Contains(text.volumes, addonPostgresVolume) {
		t.Errorf("имя тома разошлось: модель %q, текст %q", volume, text.volumes)
	}
}

// Столкновение имени сервиса — отказ, а не подмена чужой базы нашей.
func TestInjectAddonsRefusesNameCollision(t *testing.T) {
	model := map[string]any{"services": map[string]any{
		"web": map[string]any{"image": "web:1"},
		"db":  map[string]any{"image": "mysql:8"},
	}}

	_, err := injectAddons(model, []AddonSpec{{
		Kind: "postgres", Service: "db",
		Image: "postgres:17-alpine@sha256:" + strings.Repeat("a", 64),
	}}, map[string]bool{"web": true})
	if err == nil {
		t.Fatal("чужой сервис db молча подменён нашей базой")
	}
	if !strings.Contains(err.Error(), "db") {
		t.Errorf("отказ не называет сервис: %v", err)
	}
	// Чужой сервис остался нетронутым.
	services := model["services"].(map[string]any)
	svc := services["db"].(map[string]any)
	if svc["image"] != "mysql:8" {
		t.Errorf("чужой сервис затёрт: %v", svc)
	}
}

// Обычный случай: сервис и том появляются, авторские не задеты.
func TestInjectAddonsAddsServiceAndVolume(t *testing.T) {
	model := map[string]any{"services": map[string]any{
		"web": map[string]any{"build": "."},
	}}

	notes, err := injectAddons(model, []AddonSpec{{
		Kind: "postgres", Service: "db",
		Image: "postgres:17-alpine@sha256:" + strings.Repeat("a", 64),
	}}, map[string]bool{"web": true})
	if err != nil {
		t.Fatalf("вживление не прошло: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("человек не узнает, что стек изменили: %v", notes)
	}

	services := model["services"].(map[string]any)
	if _, ok := services["db"]; !ok {
		t.Fatal("сервис базы не добавлен")
	}
	if web, ok := services["web"].(map[string]any); !ok || web["build"] != "." {
		t.Errorf("авторский сервис задет: %v", services["web"])
	}
	vols, ok := model["volumes"].(map[string]any)
	if !ok {
		t.Fatal("секция volumes не заведена — данные легли бы в анонимный том")
	}
	if _, ok := vols[addonPostgresVolume]; !ok {
		t.Errorf("том базы не объявлен: %v", vols)
	}
}

// Опубликованный сервис ждёт ГОТОВНОСТИ базы, а не её запуска.
//
// Без связи compose поднимает приложение и базу разом, и миграции на старте
// бьют в postgres, который ещё не принимает соединения: контейнер уходит в цикл
// перезапуска, `up --wait` признаёт стек негодным, а человек читает «стек не
// поднялся» и ищет ошибку в своём коде.
func TestInjectAddonsMakesAppWaitForDatabase(t *testing.T) {
	model := map[string]any{"services": map[string]any{
		"web": map[string]any{"build": "."},
	}}

	if _, err := injectAddons(model, []AddonSpec{{
		Kind: "postgres", Service: "db",
		Image: "postgres:17-alpine@sha256:" + strings.Repeat("a", 64),
	}}, map[string]bool{"web": true}); err != nil {
		t.Fatalf("вживление не прошло: %v", err)
	}

	web := model["services"].(map[string]any)["web"].(map[string]any)
	deps, ok := web["depends_on"].(map[string]any)
	if !ok {
		t.Fatal("приложение не ждёт базу вовсе")
	}
	cond, ok := deps["db"].(map[string]any)
	if !ok || cond["condition"] != "service_healthy" {
		t.Fatalf("ждём не готовности, а чего-то другого: %v", deps["db"])
	}
}

// Авторские зависимости не затираются: у клиента могут быть свои связи между
// сервисами, и заменить их нашей значило бы сломать задуманный порядок.
func TestInjectAddonsKeepsAuthorDependencies(t *testing.T) {
	model := map[string]any{"services": map[string]any{
		"web":    map[string]any{"build": ".", "depends_on": []any{"worker"}},
		"worker": map[string]any{"image": "worker:1"},
	}}

	if _, err := injectAddons(model, []AddonSpec{{
		Kind: "postgres", Service: "db",
		Image: "postgres:17-alpine@sha256:" + strings.Repeat("a", 64),
	}}, map[string]bool{"web": true}); err != nil {
		t.Fatalf("вживление не прошло: %v", err)
	}

	deps := model["services"].(map[string]any)["web"].(map[string]any)["depends_on"].(map[string]any)
	if _, ok := deps["worker"]; !ok {
		t.Error("авторская зависимость на worker потеряна")
	}
	if _, ok := deps["db"]; !ok {
		t.Error("зависимость на базу не добавлена")
	}
}

// Синтетический стек связан тем же условием.
func TestSyntheticAddonsDependsOnHealthy(t *testing.T) {
	out, err := renderAddonServices([]AddonSpec{{
		Kind: "postgres", Service: "db",
		Image: "postgres:17-alpine@sha256:" + strings.Repeat("a", 64),
	}})
	if err != nil {
		t.Fatalf("рендер: %v", err)
	}
	if !strings.Contains(out.dependsOn, "db:") || !strings.Contains(out.dependsOn, "service_healthy") {
		t.Fatalf("синтетический стек не ждёт готовности базы: %q", out.dependsOn)
	}
}
