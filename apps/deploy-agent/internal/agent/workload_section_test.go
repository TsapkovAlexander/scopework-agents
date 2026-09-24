package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Контракт секции workloads (ADR-0091, решение 1). Точка правды —
// packages/server-monitoring/src/workloads.ts и её золотая фикстура: поле,
// добавленное на одной стороне и забытое на другой, падает здесь, а не
// отказом всей секции на платформе.

func workloadsContractPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "..", "packages", "server-monitoring"}, parts...)...)
}

func loadWorkloadsFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(workloadsContractPath("fixtures", "workloads-section.json"))
	if err != nil {
		t.Fatalf("не удалось прочитать эталон секции: %v", err)
	}
	return raw
}

func TestWorkloadSectionMatchesFixture(t *testing.T) {
	raw := loadWorkloadsFixture(t)

	var section WorkloadsSection
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&section); err != nil {
		t.Fatalf("эталон не разбирается типами агента: %v", err)
	}
	if len(section.Containers) != 5 || len(section.Volumes) != 3 || len(section.Buckets) != 2 || len(section.Events) != 2 {
		t.Fatalf("секция разобрана не целиком: %+v", section)
	}

	again, err := json.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	// Сравнение по смыслу, а не по байтам: порядок ключей и пробелы фикстуры —
	// её оформление. Отсутствующий ключ и null здесь различаются: контракт
	// требует каждый ключ всегда.
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(again, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("сериализация агента расходится с эталоном:\n%s", again)
	}
}

// Пустые значения обязаны давать все ключи: nil-срез маршалится в null, и
// платформа отвергла бы секцию целиком.
func TestWorkloadZeroRowsKeepEveryKey(t *testing.T) {
	cases := map[string]struct {
		value any
		keys  int
	}{
		"container":        {WorkloadContainer{}, 15},
		"image":            {WorkloadImage{}, 6},
		"cgroup":           {WorkloadCgroup{}, 8},
		"network":          {WorkloadNetwork{}, 9},
		"volume":           {WorkloadVolume{}, 9},
		"bucket":           {WorkloadBucket{}, 6},
		"bucket container": {WorkloadBucketContainer{}, 9},
		"bucket volume":    {WorkloadBucketVolume{}, 4},
		"event":            {WorkloadEvent{}, 14},
		"section":          {WorkloadsSection{}, 12},
	}
	for name, tc := range cases {
		raw, err := json.Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		var keys map[string]any
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Fatal(err)
		}
		if len(keys) != tc.keys {
			t.Errorf("%s: %d ключей, ожидалось %d: %s", name, len(keys), tc.keys, raw)
		}
	}
}

func TestWorkloadTimestampIsUTCWithZ(t *testing.T) {
	local := time.FixedZone("UTC+7", 7*3600)
	cases := map[string]time.Time{
		// Граница корзины — без дробной части, как в эталоне.
		"2026-09-23T03:00:00Z":           time.Date(2026, 9, 23, 10, 0, 0, 0, local),
		"2026-09-23T09:58:12.907Z":       time.Date(2026, 9, 23, 9, 58, 12, 907000000, time.UTC),
		"2026-09-23T10:02:17.540218123Z": time.Date(2026, 9, 23, 10, 2, 17, 540218123, time.UTC),
		"2026-09-23T10:00:00.000000001Z": time.Date(2026, 9, 23, 17, 0, 0, 1, local),
	}
	for want, at := range cases {
		if got := workloadTimestamp(at); got != want {
			t.Errorf("%v: %q, ожидалось %q", at, got, want)
		}
	}
}

func TestWorkloadDockerTime(t *testing.T) {
	cases := map[string]*string{
		"":                               nil,
		"0001-01-01T00:00:00Z":           nil,
		"не время":                       nil,
		"2026-09-23T10:02:17.540218123Z": strPtr("2026-09-23T10:02:17.540218123Z"),
		"2026-09-23T17:02:17+07:00":      strPtr("2026-09-23T10:02:17Z"),
	}
	for raw, want := range cases {
		got := workloadDockerTime(raw)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%q: %v, ожидалось %v", raw, deref(got), deref(want))
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// Отсутствие поля — «не доставлено», в отличие от прочих секций (ADR-0091,
// решение 1): иначе старая платформа подтверждала бы секцию молчанием, и
// агент стирал бы очередь событий.
func TestWorkloadsAcceptedOnlyExactOne(t *testing.T) {
	cases := map[string]bool{
		``:                       false,
		`null`:                   false,
		`{`:                      false,
		`[]`:                     false,
		`{}`:                     false,
		`{"traffic":1}`:          false,
		`{"workloads":1}`:        true,
		`{"workloads": 1 }`:      true,
		`{"workloads":-1}`:       false,
		`{"workloads":0}`:        false,
		`{"workloads":"1"}`:      false,
		`{"workloads":1.5}`:      false,
		`{"workloads":null}`:     false,
		`{"workloads":true}`:     false,
		`{"workloads":[1]}`:      false,
		`{"workloads":{"n":1}}`:  false,
		`{"workloads":2}`:        false,
		`{"workloads":1,"x":-1}`: true,
	}
	for accepted, want := range cases {
		resp := TickResponse{Accepted: json.RawMessage(accepted)}
		if got := WorkloadsAccepted(resp); got != want {
			t.Errorf("accepted %q: %v, ожидалось %v", accepted, got, want)
		}
	}
}

func TestWorkloadTickRequestCarriesSection(t *testing.T) {
	raw, err := json.Marshal(TickRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"workloads"`) {
		t.Fatalf("секции нет — ключа быть не должно: %s", raw)
	}

	raw, err = json.Marshal(TickRequest{Workloads: &WorkloadsSection{Version: WorkloadsSectionVersion}})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["workloads"]; !ok {
		t.Fatalf("секция не попала в тело такта: %s", raw)
	}
}

// Пределы агента и платформы обязаны совпадать: платформа отвергает секцию
// целиком, и расхождение на единицу стоило бы хосту всех рядов.
func TestWorkloadLimitsMatchContract(t *testing.T) {
	src, err := os.ReadFile(workloadsContractPath("src", "workloads.ts"))
	if err != nil {
		t.Fatalf("не удалось прочитать контракт: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^(?:export )?const (WORKLOADS_[A-Z_]+|MAX_BUCKET_SAMPLES) = ([0-9 *]+)(?: as const)?;`)
	found := map[string]int{}
	for _, m := range decl.FindAllStringSubmatch(string(src), -1) {
		product := 1
		for _, factor := range strings.Split(m[2], "*") {
			n, err := strconv.Atoi(strings.TrimSpace(factor))
			if err != nil {
				t.Fatalf("%s: не число %q", m[1], m[2])
			}
			product *= n
		}
		found[m[1]] = product
	}

	want := map[string]int{
		"WORKLOADS_SECTION_VERSION":     WorkloadsSectionVersion,
		"WORKLOADS_MAX_CONTAINERS":      WorkloadsMaxContainers,
		"WORKLOADS_MAX_VOLUMES":         WorkloadsMaxVolumes,
		"WORKLOADS_MAX_PEERS":           WorkloadsMaxPeers,
		"WORKLOADS_MAX_EVENTS":          WorkloadsMaxEvents,
		"WORKLOADS_MAX_BUCKETS":         WorkloadsMaxBuckets,
		"WORKLOADS_BUCKET_SECONDS":      WorkloadsBucketSeconds,
		"WORKLOADS_MAX_SECTION_BYTES":   WorkloadsMaxSectionBytes,
		"WORKLOADS_MAX_TICK_BODY_BYTES": WorkloadsMaxTickBodyBytes,
		"MAX_BUCKET_SAMPLES":            workloadMaxBucketSamples,
	}
	for name, value := range want {
		got, ok := found[name]
		if !ok {
			t.Errorf("%s не найден в workloads.ts — сверка не проведена", name)
			continue
		}
		if got != value {
			t.Errorf("%s: у платформы %d, у агента %d", name, got, value)
		}
	}
}
