package hoststate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

// Общая фикстура выбора версии: по ней же проверяет себя web
// (agentProtocol.test.ts). Разойдись выбор на двух сторонах — платформа
// отдала бы агенту содержимое, которого тот не исполняет.
func TestNegotiateFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixturesDir(), "protocol-negotiation.json"))
	if err != nil {
		t.Fatalf("нет фикстуры (сгенерировать: %s=1 go test -run TestSigningFixtures ./pkg/hoststate/): %v", updateFixturesEnv, err)
	}
	var f negotiationFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// Фикстура обязана покрывать случаи, ради которых она есть.
	for _, name := range []string{
		"legacy-agent-without-declaration", "agent-without-roots", "agent-only-unknown-content",
		"agent-with-both-versions-gets-highest", "leading-zero-is-not-a-version",
	} {
		found := false
		for _, c := range f.Cases {
			found = found || c.Name == name
		}
		if !found {
			t.Errorf("в фикстуре нет случая %s", name)
		}
	}
	checkNegotiation(t, f)
}

func TestNegotiatePicksHighestCommonVersion(t *testing.T) {
	platform := hoststate.Protocol{
		Content:   []string{"host-state/0", "host-state/1", "host-state/2"},
		Envelopes: []string{"dsse-ed25519/1", "dsse-ed25519/2"},
	}
	cases := []struct {
		name     string
		declared *hoststate.Protocol
		want     hoststate.Choice
		legacy   bool
	}{
		{
			name:     "наибольшая из пересечения, а не из объявленного",
			declared: &hoststate.Protocol{Content: []string{"host-state/0", "host-state/1", "host-state/7"}, Envelopes: []string{"dsse-ed25519/1"}},
			want:     hoststate.Choice{Envelope: "dsse-ed25519/1", Content: "host-state/1"},
		},
		{
			name:     "порядок в объявлении не важен",
			declared: &hoststate.Protocol{Content: []string{"host-state/2", "host-state/0"}, Envelopes: []string{"dsse-ed25519/2", "dsse-ed25519/1"}},
			want:     hoststate.Choice{Envelope: "dsse-ed25519/2", Content: "host-state/2"},
		},
		{
			name:     "содержимого без пересечения нет",
			declared: &hoststate.Protocol{Content: []string{"host-state/9"}, Envelopes: []string{"dsse-ed25519/1"}},
			want:     hoststate.Choice{Envelope: "dsse-ed25519/1"},
		},
		{
			name:     "мусор в объявлении не выбирается",
			declared: &hoststate.Protocol{Content: []string{"host-state/-1", "host-state/01", "host-state/+1", "host-state/0"}, Envelopes: []string{"dsse-ed25519", "dsse-ed25519/x"}},
			want:     hoststate.Choice{Content: "host-state/0"},
		},
		{
			name:   "legacy получает host-state/0 без обёртки",
			want:   hoststate.Choice{Content: "host-state/0"},
			legacy: true,
		},
	}
	for _, c := range cases {
		got, legacy := hoststate.Negotiate(c.declared, platform)
		if got != c.want || legacy != c.legacy {
			t.Errorf("%s: got %+v legacy=%v, want %+v legacy=%v", c.name, got, legacy, c.want, c.legacy)
		}
	}
}

// Число после «/» сравнивается как число: при строковом сравнении
// host-state/10 оказался бы меньше host-state/9.
func TestNegotiateComparesNumbers(t *testing.T) {
	platform := hoststate.Protocol{Content: []string{"host-state/9", "host-state/10"}}
	got, _ := hoststate.Negotiate(&hoststate.Protocol{Content: []string{"host-state/9", "host-state/10"}}, platform)
	if got.Content != "host-state/10" {
		t.Fatalf("выбрано %q", got.Content)
	}
}

// Платформа, снявшая host-state/0, legacy-агенту не отдаёт ничего: ответ не
// 2xx, а не пустое состояние (ADR-0093, решение 3) — пустое старый агент
// применил бы как «снять всё».
func TestNegotiateLegacyWithoutV0(t *testing.T) {
	got, legacy := hoststate.Negotiate(nil, hoststate.Protocol{Content: []string{"host-state/1"}})
	if !legacy || got != (hoststate.Choice{}) {
		t.Fatalf("got %+v legacy=%v", got, legacy)
	}
}

func TestPayloadTypeForContent(t *testing.T) {
	if got, ok := hoststate.PayloadTypeFor("host-state/0"); !ok || got != "application/vnd.scopework.host-state+json;v=0" {
		t.Fatalf("host-state/0 → %q %v", got, ok)
	}
	if got, ok := hoststate.PayloadTypeFor("host-state/1"); !ok || got != "application/vnd.scopework.host-state+json;v=1" {
		t.Fatalf("host-state/1 → %q %v", got, ok)
	}
	for _, bad := range []string{"", "host-state", "host-state/x", "host-state/01", "other/0"} {
		if _, ok := hoststate.PayloadTypeFor(bad); ok {
			t.Errorf("%q принят", bad)
		}
	}
	if hoststate.PayloadTypeHostStateV0 != "application/vnd.scopework.host-state+json;v=0" {
		t.Fatalf("PayloadTypeHostStateV0 = %q", hoststate.PayloadTypeHostStateV0)
	}
}

// Агент объявляет ровно то, что проверяет Verifier: объявить больше значит
// получить пакет, от которого откажешься. Без корней обёрток нет — пустой
// список, а не null: платформа отличает «не проверяю» от «не объявил».
func TestAgentProtocolDeclaresWhatVerifierSupports(t *testing.T) {
	withRoots := hoststate.AgentProtocol(true)
	want := hoststate.Protocol{Content: []string{hoststate.ContentV0}, Envelopes: []string{hoststate.EnvelopeDSSE}}
	if !reflect.DeepEqual(withRoots, want) {
		t.Fatalf("объявление с корнями: %+v", withRoots)
	}
	raw, err := json.Marshal(hoststate.AgentProtocol(false))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"content":["host-state/0"],"envelopes":[]}` {
		t.Fatalf("объявление без корней: %s", raw)
	}
	withRoots.Content[0] = "испорчено"
	if hoststate.AgentProtocol(true).Content[0] != hoststate.ContentV0 {
		t.Fatal("объявление агента меняется снаружи")
	}
}
