package hoststate_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

func TestValidSecretRef(t *testing.T) {
	good := []string{
		"app/backend/env/DB_PASSWORD", "app/backend/env/_x1", "app/sigma-supabase/gitKey",
		"app/site/gitToken", "registry/ghcr.io/token", "registry/registry.example.com:5000/token",
		"objectStorage/secretAccessKey",
	}
	bad := []string{
		"", "app/backend", "app/backend/env/", "app/backend/env/1X", "app/backend/env/A-B",
		"app/Backend/gitKey", "app/backend/gitkey", "app/backend/env/A/B", "app//gitKey",
		"registry//token", "registry/ghcr.io/username", "registry/GHCR.io/token",
		"objectStorage/accessKeyId", "host/rootPassword", "app/backend/gitKey/",
	}
	for _, r := range good {
		if !hoststate.ValidSecretRef(r) {
			t.Errorf("%q отвергнута", r)
		}
	}
	for _, r := range bad {
		if hoststate.ValidSecretRef(r) {
			t.Errorf("%q принята", r)
		}
	}
}

func TestSecretValuesMatch(t *testing.T) {
	refs := []string{"a", "b"}
	if !hoststate.SecretValuesMatch(refs, map[string]string{"a": "", "b": "2"}) {
		t.Fatal("совпадающий набор отвергнут (пустое значение — тоже значение)")
	}
	if !hoststate.SecretValuesMatch(nil, nil) || !hoststate.SecretValuesMatch([]string{}, map[string]string{}) {
		t.Fatal("пустой набор отвергнут")
	}
	for name, values := range map[string]map[string]string{
		"не хватает": {"a": "1"},
		"лишнее":     {"a": "1", "b": "2", "c": "3"},
		"другое":     {"a": "1", "c": "3"},
	} {
		if hoststate.SecretValuesMatch(refs, values) {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestAssembleStateV0(t *testing.T) {
	state := json.RawMessage(`{
		"apps":[
			{"slug":"backend","env":{"NODE_ENV":"production","DB_PASSWORD":"открытое"},"gitKey":null,"gitToken":null,"internalPort":3000},
			{"slug":"site","env":null,"gitKey":null,"gitToken":null}
		],
		"registries":[{"registry":"ghcr.io","username":"bot","token":""}],
		"denyIps":[],"platformSubdomainBase":"apps.example.com",
		"objectStorage":{"bucket":"b","secretAccessKey":"","partSizeBytes":8388608}
	}`)
	values := map[string]string{
		"app/backend/env/DB_PASSWORD":   "секрет",
		"app/backend/gitKey":            "key",
		"app/site/env/TOKEN":            "t",
		"app/site/gitToken":             "gt",
		"registry/ghcr.io/token":        "rt",
		"objectStorage/secretAccessKey": "sk",
	}
	refs := make([]string, 0, len(values))
	for r := range values {
		refs = append(refs, r)
	}
	got, err := hoststate.AssembleStateV0(state, refs, values)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"apps":[
		{"slug":"backend","env":{"NODE_ENV":"production","DB_PASSWORD":"секрет"},"gitKey":"key","gitToken":null,"internalPort":3000},
		{"slug":"site","env":{"TOKEN":"t"},"gitKey":null,"gitToken":"gt"}
	],"registries":[{"registry":"ghcr.io","username":"bot","token":"rt"}],
	"denyIps":[],"platformSubdomainBase":"apps.example.com",
	"objectStorage":{"bucket":"b","secretAccessKey":"sk","partSizeBytes":8388608}}`
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("собрано:\n%s", got)
	}
	// Большое целое не превращается в число с плавающей точкой.
	if !strings.Contains(string(got), `"partSizeBytes":8388608`) {
		t.Fatalf("число испорчено: %s", got)
	}
}

func TestAssembleStateV0RejectsDanglingRefs(t *testing.T) {
	state := json.RawMessage(`{"apps":[{"slug":"a","env":{}},{"slug":"a","env":{}}],"registries":[]}`)
	for _, ref := range []string{"app/b/gitKey", "app/a/gitKey", "registry/ghcr.io/token", "objectStorage/secretAccessKey"} {
		if _, err := hoststate.AssembleStateV0(state, []string{ref}, map[string]string{ref: "x"}); err == nil {
			t.Errorf("%s: собрано без цели", ref)
		}
	}
}
