package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Контракт подписанного ответа между web и агентом.
//
// Фикстуры генерирует pkg/hoststate, читает TypeScript. Здесь проверяется
// третья сторона стыка — структуры агента: пакет, который проходит проверку в
// общем пакете, агент обязан собрать в то же желаемое состояние, что приезжало
// неподписанным. Иначе поле, известное web и незнакомое агенту, отказывало бы
// каждому хосту с корнями как «содержимое новее агента».

func readContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "packages", "deploy-core", "fixtures", name))
	if err != nil {
		t.Fatalf("не удалось прочитать эталон контракта: %v", err)
	}
	return raw
}

func TestSignedTickResponseFixture(t *testing.T) {
	var fx struct {
		RootPublicKeys   []string        `json:"rootPublicKeys"`
		Now              string          `json:"now"`
		AgentFingerprint string          `json:"agentFingerprint"`
		Response         json.RawMessage `json:"response"`
		LatchAfter       hoststate.Latch `json:"latchAfter"`
	}
	if err := signenv.DecodeStrict(readContractFixture(t, "tick-response-signed.json"), &fx); err != nil {
		t.Fatalf("эталон не разбирается: %v", err)
	}
	useStateRoots(t, strings.Join(fx.RootPublicKeys, ","))
	now := mustParseTime(t, fx.Now)

	// Ответ разбирается тем же типом, что боевой такт.
	var resp TickResponse
	if err := json.Unmarshal(fx.Response, &resp); err != nil {
		t.Fatalf("ответ такта не разбирается: %v", err)
	}
	dir := t.TempDir()
	c := NewClient("http://127.0.0.1", "test")
	c.UseStateDir(dir)
	c.now = func() time.Time { return now }

	c.acceptState(fx.AgentFingerprint, &resp.DesiredState, resp.SignedState, resp.StateWithheld)

	if !resp.DesiredState.Accepted {
		t.Fatalf("пакет эталона не принят: %+v", c.lastSigning)
	}
	latch, err := loadStateLatch(dir, fx.AgentFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if latch != fx.LatchAfter {
		t.Fatalf("защёлка %+v, в эталоне %+v", latch, fx.LatchAfter)
	}

	want := loadDesiredStateFixture(t)
	want.Accepted = true
	// Хеш нагрузки — тот же, что в защёлке: им локальный журнал записывает
	// приход подписанного состояния.
	want.SignedPayloadSHA256 = fx.LatchAfter.PayloadSHA256
	if !reflect.DeepEqual(resp.DesiredState, want) {
		got, _ := json.MarshalIndent(resp.DesiredState, "", "  ")
		t.Fatalf("собранное состояние не равно desired-state.json:\n%s", got)
	}
}

// Разрез web: состояние без значений секретов плюс значения рядом. Сборка
// агентом обязана дать ровно desired-state.json — в тех же структурах и тем
// же строгим разбором, что у подписанного пакета.
func TestSplitFixtureAssemblesDesiredState(t *testing.T) {
	var fx struct {
		Payload      json.RawMessage   `json:"payload"`
		SecretValues map[string]string `json:"secretValues"`
		State        json.RawMessage   `json:"state"`
		Secrets      []string          `json:"secrets"`
		Values       map[string]string `json:"values"`
	}
	if err := signenv.DecodeStrict(readContractFixture(t, "signed-state-split.json"), &fx); err != nil {
		t.Fatalf("эталон не разбирается: %v", err)
	}
	assembled, err := hoststate.AssembleStateV0(fx.State, fx.Secrets, fx.Values)
	if err != nil {
		t.Fatalf("разрез не собирается: %v", err)
	}
	got, reason, err := decodeSignedDesiredState(assembled)
	if err != nil {
		t.Fatalf("собранное состояние отвергнуто строгим разбором (%s): %v", reason, err)
	}
	want := loadDesiredStateFixture(t)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("собранное из разреза не равно desired-state.json")
	}

	// Без значений секретов состояние неполное: ключ репозитория пуст.
	var redacted DesiredState
	if err := json.Unmarshal(fx.State, &redacted); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(redacted, want) {
		t.Fatal("разрез ничего не вынес из состояния — проверка сборки пуста")
	}
}
