package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Приход подписанного состояния в локальном журнале (контракт К↔Г).
//
// Агент с корнями получает состояние только конвертом: плоских полей в ответе
// нет, а пришедшие не применяются. Строка прихода обязана нести sha256 байтов
// нагрузки DSSE — тот же хеш пишет журнал отправленного на платформе, — и не
// появляться на тактах, где пакета не было: состояние в памяти их переживает.
func TestSignedStateJournalHashIsPayloadHash(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.SetTrustedStateRootsForTest(base64.StdEncoding.EncodeToString(pub)))
	withPolicyFile(t, "version=1\nmode=deploy\n")

	host := newPolicyHost(t)
	local := &localControl{
		journal: agent.OpenJournal(host.journal, io.Discard, "test"),
		trust:   agent.NewTrustReport(""),
	}
	payloadHash := strings.Repeat("ab", 32)
	signed := agent.DesiredState{
		Apps:                []agent.DesiredApp{{Slug: "shop", Desired: "present", ReleaseID: "release-1"}},
		Accepted:            true,
		SignedPayloadSHA256: payloadHash,
	}
	// Плоские поля рядом с пакетом: агент с корнями их не применяет, и хеш по
	// ним в журнал попасть не должен.
	const withFlat = `{"hostId":"h1","apps":[{"slug":"evil","desired":"present"}],"signedState":{}}`
	const withheld = `{"hostId":"h1","stateWithheld":"signer_unavailable"}`

	step := func(raw string, state agent.DesiredState, adopted agent.DesiredState) (string, bool) {
		t.Helper()
		resp := agent.TickResponse{DesiredState: state, Raw: json.RawMessage(raw)}
		local.received(resp, agent.NewReportGate(), false)
		var report agent.TickRequest
		local.beginTick(&report, nil, adopted, true)
		return local.stateHash, local.stateFresh
	}

	if hash, fresh := step(withFlat, signed, signed); hash != payloadHash || !fresh {
		t.Fatalf("приход подписанного записан хешем %q (fresh=%v), ожидался хеш нагрузки", hash, fresh)
	}
	// Удержание: пакета нет, в памяти прежнее состояние — строки прихода нет.
	if hash, fresh := step(withheld, agent.DesiredState{}, signed); hash != "" || fresh {
		t.Fatalf("такт без пакета записал приход %q (fresh=%v)", hash, fresh)
	}

	raw, err := os.ReadFile(host.journal)
	if err != nil {
		t.Fatal(err)
	}
	flatHash := agent.CommandHashes([]byte(withFlat)).State
	receives := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e agent.JournalEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.Type != "receive" || e.Kind != agent.JournalKindDesiredState {
			continue
		}
		if e.Hash == flatHash {
			t.Fatalf("в журнал попал хеш плоских полей при корнях:\n%s", raw)
		}
		receives++
	}
	if receives != 1 {
		t.Fatalf("строк прихода состояния %d, ожидалась 1:\n%s", receives, raw)
	}
}

// Без корней удержание тоже не пишет прихода: состояние в памяти переживает
// ответ без apps, а сырых байтов состояния в нём нет.
func TestUnsignedWithheldWritesNoReceive(t *testing.T) {
	withPolicyFile(t, "version=1\nmode=deploy\n")
	host := newPolicyHost(t)
	local := &localControl{
		journal: agent.OpenJournal(host.journal, io.Discard, "test"),
		trust:   agent.NewTrustReport(""),
	}
	kept := agent.DesiredState{Apps: []agent.DesiredApp{{Slug: "shop", Desired: "present", ReleaseID: "release-1"}}}
	resp := agent.TickResponse{Raw: json.RawMessage(`{"hostId":"h1","stateWithheld":"policy"}`)}
	local.received(resp, agent.NewReportGate(), false)
	var report agent.TickRequest
	local.beginTick(&report, nil, kept, true)
	if local.stateHash != "" || local.stateFresh {
		t.Fatalf("удержание записало приход %q", local.stateHash)
	}
}
