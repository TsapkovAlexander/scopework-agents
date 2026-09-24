package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Строки /proc/<pid>/net/tcp{,6} ниже — в том виде, в каком их печатает ядро
// на little-endian машине (amd64, arm64): адрес — 32-битные слова в порядке
// байтов машины, порт — в порядке хоста. Адреса записаны литералами, а не
// кодировщиком из теста: иначе тест проверял бы декодер его же обращением.

const (
	tcpEstablished = "01"
	tcpListen      = "0A"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpLine(local, remote, state string) string {
	return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 20 4 30 10 -1\n",
		local, remote, state)
}

func writeProcNet(t *testing.T, proc string, pid int, tcp, tcp6 *string) {
	t.Helper()
	dir := filepath.Join(proc, fmt.Sprint(pid), "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]*string{"tcp": tcp, "tcp6": tcp6} {
		if content == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(tcpHeader+*content), 0o444); err != nil {
			t.Fatal(err)
		}
	}
}

func tcpTestAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func tcpPeersString(peers []TCPPeer) string {
	parts := make([]string, 0, len(peers))
	for _, p := range peers {
		parts = append(parts, fmt.Sprintf("%s:%d/%s×%d", p.Address, p.Port, p.Direction, p.Count))
	}
	return strings.Join(parts, " ")
}

func TestProcNetDecodesLittleEndianAddresses(t *testing.T) {
	cases := []struct {
		hex, want string
		port      int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},
		{"030012AC:1538", "172.18.0.3", 5432},
		{"090E4864:0BB8", "100.72.14.9", 3000},
		{"00000000000000000000000001000000:01BB", "::1", 443},
		{"563412FD00009A780000000005000000:18EB", "fd12:3456:789a::5", 6379},
		// ::ffff:a.b.c.d — IPv4-соединение, принятое двухстековым сокетом.
		// Оно обязано выглядеть как IPv4: иначе один и тот же пир жил бы в
		// ключе группировки под двумя именами.
		{"0000000000000000FFFF0000050012AC:0050", "172.18.0.5", 80},
	}
	for _, c := range cases {
		ap, ok := tcpParseEndpoint(c.hex)
		if !ok {
			t.Fatalf("%s не разобран", c.hex)
		}
		if ap.Addr().String() != c.want || int(ap.Port()) != c.port {
			t.Fatalf("%s → %s, ожидалось %s:%d", c.hex, ap, c.want, c.port)
		}
	}
	for _, bad := range []string{"", "0100007F", "0100007F:", "ZZ00007F:1F90", "01007F:1F90", "0100007F:1F90:1"} {
		if _, ok := tcpParseEndpoint(bad); ok {
			t.Fatalf("мусор %q разобран как адрес", bad)
		}
	}
}

// Направление — по LISTEN-портам того же netns, из обоих файлов: слушатель на
// [::] лежит в tcp6, а принятые им IPv4-соединения — там же, как ::ffff:.
func TestProcNetCountsDirectionByListenPorts(t *testing.T) {
	proc := t.TempDir()
	tcp := tcpLine("00000000:0BB8", "00000000:0000", tcpListen) + // 0.0.0.0:3000
		tcpLine("020012AC:0BB8", "010012AC:C738", tcpEstablished) + // 172.18.0.2:3000 ← 172.18.0.1
		tcpLine("020012AC:9C41", "030012AC:1538", tcpEstablished) + // 172.18.0.2 → 172.18.0.3:5432
		tcpLine("020012AC:9C42", "030012AC:1538", tcpEstablished) +
		// Не ESTABLISHED — не соединение: TIME_WAIT, SYN_SENT, CLOSE_WAIT.
		tcpLine("020012AC:9C43", "030012AC:1538", "06") +
		tcpLine("020012AC:9C44", "030012AC:1538", "02") +
		tcpLine("020012AC:9C45", "030012AC:1538", "08")
	tcp6 := tcpLine("00000000000000000000000000000000:1F90", "00000000000000000000000000000000:0000", tcpListen) + // [::]:8080
		tcpLine("0000000000000000FFFF0000020012AC:1F90", "0000000000000000FFFF00000700000A:9C40", tcpEstablished) // ← 10.0.0.7
	writeProcNet(t, proc, 4242, strp(tcp), strp(tcp6))

	got := ReadNetnsTCP(proc, 4242, 32)
	if got.Status != "ok" || got.Reason != "" || got.NetnsOwner != "" {
		t.Fatalf("статус %q/%q/%q, ожидалось ok", got.Status, got.Reason, got.NetnsOwner)
	}
	if got.Established != 4 || got.Inbound != 2 || got.Outbound != 2 || got.External != 0 {
		t.Fatalf("счёт %+v, ожидалось 4 = 2 входящих + 2 исходящих, внешних 0", got)
	}
	// Входящий — порт своего сервиса, исходящий — порт пира; эфемерный порт в
	// ключ не идёт, поэтому два соединения к базе — один пир с count 2.
	want := "172.18.0.3:5432/out×2 10.0.0.7:8080/in×1 172.18.0.1:3000/in×1"
	if s := tcpPeersString(got.Peers); s != want {
		t.Fatalf("пиры %q, ожидалось %q", s, want)
	}
	if got.PeersTruncated {
		t.Fatal("пиры помечены усечёнными без причины")
	}
}

// Адрес публичного пира — посетитель приложения клиента: с хоста уходит только
// сумма (ADR-0091, решение 4).
func TestProcNetPublicPeersOnlyAsSum(t *testing.T) {
	proc := t.TempDir()
	tcp := tcpLine("00000000:01BB", "00000000:0000", tcpListen) +
		tcpLine("020012AC:01BB", "08080808:C738", tcpEstablished) + // ← 8.8.8.8
		tcpLine("020012AC:01BB", "08080808:C739", tcpEstablished) +
		tcpLine("020012AC:9C41", "0404A8C0:1538", tcpEstablished) + // → 192.168.4.4:5432
		tcpLine("020012AC:9C42", "01010101:0035", tcpEstablished) // → 1.1.1.1:53
	tcp6 := tcpLine("00000000000000000000000000000000:01BB", "00000000000000000000000000000000:0000", tcpListen) + // [::]:443
		tcpLine("000000FD000000000000000002000000:01BB", "B80D0120000000000000000001000000:C740", tcpEstablished) // fd00::2:443 ← 2001:db8::1
	writeProcNet(t, proc, 4242, strp(tcp), strp(tcp6))

	got := ReadNetnsTCP(proc, 4242, 32)
	if got.Established != 5 || got.External != 4 {
		t.Fatalf("счёт %+v, ожидалось 5 соединений, из них 4 внешних", got)
	}
	if got.Inbound != 3 || got.Outbound != 2 {
		t.Fatalf("направления %+v, ожидалось 3 входящих и 2 исходящих", got)
	}
	if s := tcpPeersString(got.Peers); s != "192.168.4.4:5432/out×1" {
		t.Fatalf("пиры %q: публичный адрес ушёл адресом или частный потерян", s)
	}
}

// Набор внутренних обязан совпасть с isInternalAddress контракта
// (packages/server-monitoring/src/workloads.ts): адрес, который агент отдал
// пиром, а платформа сочла публичным, отвергает всю секцию.
func TestProcNetInternalPeerSetMatchesContract(t *testing.T) {
	internal := []string{
		"10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "127.0.0.1", "127.8.8.8",
		"169.254.1.1", "100.64.0.1", "100.127.255.254", "224.0.0.251", "0.0.0.0",
		"::1", "::", "fc00::1", "fd12:3456:789a::5", "fe80::1", "ff02::1", "ff12::2",
	}
	external := []string{
		"8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
		"224.0.1.1", "192.169.0.1", "2001:db8::1", "fec0::1", "ff05::2", "::102:304",
	}
	for _, s := range internal {
		if !netnsPeerIsInternal(tcpTestAddr(t, s)) {
			t.Fatalf("%s не признан внутренним", s)
		}
	}
	for _, s := range external {
		if netnsPeerIsInternal(tcpTestAddr(t, s)) {
			t.Fatalf("%s признан внутренним", s)
		}
	}
}

func TestProcNetTruncatesPeersToTopByCount(t *testing.T) {
	proc := t.TempDir()
	var tcp strings.Builder
	// 40 пиров 10.0.0.1…10.0.0.40 → :5432; у пира i ровно (i % 3) + 1 соединений.
	for i := 1; i <= 40; i++ {
		for c := 0; c < i%3+1; c++ {
			local := fmt.Sprintf("020012AC:%04X", 40000+i*4+c)
			remote := fmt.Sprintf("%02X00000A:1538", i)
			tcp.WriteString(tcpLine(local, remote, tcpEstablished))
		}
	}
	writeProcNet(t, proc, 4242, strp(tcp.String()), nil)

	got := ReadNetnsTCP(proc, 4242, 32)
	if len(got.Peers) != 32 || !got.PeersTruncated {
		t.Fatalf("пиров %d (усечено=%v), ожидалось 32 с пометкой", len(got.Peers), got.PeersTruncated)
	}
	// 13 пиров с count 3 (i%3 == 2), затем 14 с count 2, затем первые 5 из 13
	// с count 1 — при равенстве по адресу, чтобы усечение не прыгало от выборки
	// к выборке.
	if got.Peers[0].Address != "10.0.0.2" || got.Peers[0].Count != 3 {
		t.Fatalf("первый пир %+v, ожидалось 10.0.0.2×3", got.Peers[0])
	}
	if got.Peers[13].Address != "10.0.0.1" || got.Peers[13].Count != 2 {
		t.Fatalf("четырнадцатый пир %+v, ожидалось 10.0.0.1×2", got.Peers[13])
	}
	last := got.Peers[31]
	if last.Address != "10.0.0.15" || last.Count != 1 {
		t.Fatalf("последний пир %+v, ожидалось 10.0.0.15×1", last)
	}
	for i := 1; i < len(got.Peers); i++ {
		if got.Peers[i].Count > got.Peers[i-1].Count {
			t.Fatalf("пиры не отсортированы по count: %s", tcpPeersString(got.Peers))
		}
	}
	if got.Established != 80 || got.Outbound != 80 {
		t.Fatalf("усечение пиров задело счёт соединений: %+v", got)
	}

	none := ReadNetnsTCP(proc, 4242, 0)
	if len(none.Peers) != 0 || none.Peers == nil || !none.PeersTruncated {
		t.Fatalf("при пределе 0: пиры %v, усечено=%v", none.Peers, none.PeersTruncated)
	}
}

// Ядро с ipv6.disable=1 не создаёт tcp6 вовсе — это не «контейнер не работает».
func TestProcNetWithoutTCP6(t *testing.T) {
	proc := t.TempDir()
	writeProcNet(t, proc, 4242, strp(tcpLine("020012AC:9C41", "030012AC:1538", tcpEstablished)), nil)

	got := ReadNetnsTCP(proc, 4242, 32)
	if got.Status != "ok" || got.Established != 1 {
		t.Fatalf("без tcp6: %+v", got)
	}
}

func TestProcNetNotRunning(t *testing.T) {
	proc := t.TempDir()
	for name, pid := range map[string]int{"pid 0": 0, "отрицательный pid": -7, "процесса нет": 5151} {
		got := ReadNetnsTCP(proc, pid, 32)
		if got.Status != "unavailable" || got.Reason != "not_running" {
			t.Fatalf("%s: статус %q/%q, ожидалось unavailable/not_running", name, got.Status, got.Reason)
		}
		// Контракт требует массив, а не null: nil-срез маршалится в null.
		if got.Peers == nil {
			t.Fatalf("%s: Peers — nil", name)
		}
	}
}

const (
	netnsOwnerID = "1cf48d6c97398c2ab33dd6da957b5e7424d036cfddd9d14e1a721b888b6512b5"
	netnsSideID  = "7a0f7c2e5b6d4c3a9e8f1d2c3b4a5968778695a4b3c2d1e0f9e8d7c6b5a49382"
	netnsChainID = "b4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293"
	netnsHostID  = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
)

func TestProcNetResolveNetnsOwners(t *testing.T) {
	missing := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	loopA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	loopB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	viaHost := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	modes := map[string]string{
		netnsOwnerID: "orbita_default",
		netnsSideID:  "container:" + netnsOwnerID,
		// Docker хранит полный id владельца и допускает цепочку: сосед соседа
		// живёт в netns того же владельца.
		netnsChainID: "container:" + netnsSideID,
		netnsHostID:  "host",
		viaHost:      "container:" + netnsHostID,
		"e1":         "container:" + missing,
		"e2":         "container:",
		loopA:        "container:" + loopB,
		loopB:        "container:" + loopA,
		"n1":         "none",
		"n2":         "bridge",
		"n3":         "default",
		"n4":         "",
	}
	got := ResolveNetnsOwners(modes)

	want := map[string]NetnsAssignment{
		netnsOwnerID: {},
		netnsSideID:  {Reason: "shared_netns", Owner: netnsOwnerID},
		netnsChainID: {Reason: "shared_netns", Owner: netnsOwnerID},
		netnsHostID:  {Reason: "host_network"},
		viaHost:      {Reason: "host_network"},
		"e1":         {Reason: "netns_owner_unknown"},
		"e2":         {Reason: "netns_owner_unknown"},
		loopA:        {Reason: "netns_owner_unknown"},
		loopB:        {Reason: "netns_owner_unknown"},
		"n1":         {},
		"n2":         {},
		"n3":         {},
		"n4":         {},
	}
	if len(got) != len(want) {
		t.Fatalf("назначений %d, ожидалось %d: %+v", len(got), len(want), got)
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("%s: %+v, ожидалось %+v", id, got[id], w)
		}
	}
}
