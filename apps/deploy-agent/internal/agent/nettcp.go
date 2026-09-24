package agent

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Установленные TCP-соединения из сетевого пространства контейнера
// (ADR-0091, решения 3 и 4).
//
// /proc/<pid>/net/tcp показывает сокеты netns процесса, а не хоста, и агенту
// без root он открыт даже у root-процесса контейнера — входить в netns
// (nsenter, setns) для этого не нужно.

// TCPPeer — внутренний пир, сгруппированный по (адрес, порт, направление).
//
// Port — порт службы: свой LISTEN-порт у входящего, порт пира у исходящего.
// Эфемерный порт в ключ не идёт, иначе каждое соединение стало бы отдельным
// пиром и Count потерял бы смысл (так же записано в workloads.ts).
type TCPPeer struct {
	Address   string
	Port      int
	Direction string // "in" | "out"
	Count     int
}

// NetStats — блок `network` секции workloads. Peers никогда не nil: контракт
// требует массив, а nil-срез маршалится в null.
type NetStats struct {
	Status, Reason, NetnsOwner               string
	Established, Inbound, Outbound, External int
	Peers                                    []TCPPeer
	PeersTruncated                           bool
}

// NetnsAssignment — чей netns читать за контейнер.
//
// Reason "" — у контейнера свой netns, его сокеты читаются по его pid.
// "shared_netns" — netns принадлежит Owner: его сокеты уже сосчитаны у
// владельца, и повтор у соседа удвоил бы их. "host_network" — сокеты всего
// хоста, приписать их контейнеру нельзя. "netns_owner_unknown" — владельца
// нет среди контейнеров хоста или ссылки замкнулись в цикл.
type NetnsAssignment struct {
	Reason string
	Owner  string
}

const (
	tcpStateEstablished = "01"
	tcpStateListen      = "0A"
)

func netnsUnavailable(reason string) NetStats {
	return NetStats{Status: "unavailable", Reason: reason, Peers: []TCPPeer{}}
}

// ResolveNetnsOwners распределяет контейнеры хоста по netns.
//
// modes — id контейнера → HostConfig.NetworkMode. Docker хранит в режиме
// «container:» полный id владельца, даже если при создании назвали имя или
// короткий id (проверено на Docker 29), поэтому владелец ищется точным
// совпадением. Цепочка «сосед соседа» допустима: Docker её создаёт, и такой
// контейнер живёт в netns того же конечного владельца.
func ResolveNetnsOwners(modes map[string]string) map[string]NetnsAssignment {
	out := make(map[string]NetnsAssignment, len(modes))
	for id := range modes {
		out[id] = netnsResolve(modes, id)
	}
	return out
}

func netnsResolve(modes map[string]string, id string) NetnsAssignment {
	cur := id
	seen := map[string]bool{id: true}
	for {
		mode := modes[cur]
		if mode == "host" {
			return NetnsAssignment{Reason: "host_network"}
		}
		ref, shared := strings.CutPrefix(mode, "container:")
		if !shared {
			if cur == id {
				return NetnsAssignment{}
			}
			return NetnsAssignment{Reason: "shared_netns", Owner: cur}
		}
		if _, known := modes[ref]; !known || seen[ref] {
			return NetnsAssignment{Reason: "netns_owner_unknown"}
		}
		seen[ref] = true
		cur = ref
	}
}

// tcpSocket — установленное соединение: адреса уже без ::ffff:.
type tcpSocket struct {
	local, remote netip.AddrPort
}

// ReadNetnsTCP считает установленные соединения netns процесса pid по
// tcp и tcp6. maxPeers — сколько внутренних пиров отдать адресами; остальные
// только в счёте, с PeersTruncated.
func ReadNetnsTCP(procRoot string, pid, maxPeers int) NetStats {
	if pid <= 0 {
		return netnsUnavailable("not_running")
	}
	dir := filepath.Join(procRoot, strconv.Itoa(pid), "net")

	listen := map[uint16]bool{}
	var established []tcpSocket
	if err := tcpScanFile(filepath.Join(dir, "tcp"), listen, &established); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return netnsUnavailable("not_running")
		}
		return netnsUnavailable("read_failed")
	}
	// tcp6 нет у ядра с ipv6.disable=1 — это не остановленный контейнер.
	if err := tcpScanFile(filepath.Join(dir, "tcp6"), listen, &established); err != nil &&
		!errors.Is(err, fs.ErrNotExist) {
		return netnsUnavailable("read_failed")
	}

	s := NetStats{Status: "ok", Established: len(established)}
	type peerKey struct {
		addr netip.Addr
		port uint16
		dir  string
	}
	groups := map[peerKey]int{}
	for _, c := range established {
		// Направление — по LISTEN-портам того же netns из обоих файлов:
		// слушатель на [::] лежит в tcp6, а принятые им IPv4-соединения —
		// там же, как ::ffff:.
		k := peerKey{addr: c.remote.Addr(), port: c.remote.Port(), dir: "out"}
		if listen[c.local.Port()] {
			k.port, k.dir = c.local.Port(), "in"
			s.Inbound++
		} else {
			s.Outbound++
		}
		groups[k]++
	}

	type ranked struct {
		key   peerKey
		count int
	}
	var internal []ranked
	for k, n := range groups {
		// Публичный пир входящего — посетитель приложения клиента, его адрес —
		// данные клиента: с хоста уходит только сумма (решение 4).
		if !netnsPeerIsInternal(k.addr) {
			s.External += n
			continue
		}
		internal = append(internal, ranked{key: k, count: n})
	}
	// Порядок при равном счёте задан явно: иначе усечение отдавало бы от
	// выборки к выборке разные пиры, и список прыгал бы без изменений в сети.
	sort.Slice(internal, func(i, j int) bool {
		a, b := internal[i], internal[j]
		if a.count != b.count {
			return a.count > b.count
		}
		if c := a.key.addr.Compare(b.key.addr); c != 0 {
			return c < 0
		}
		if a.key.port != b.key.port {
			return a.key.port < b.key.port
		}
		return a.key.dir < b.key.dir
	})
	if maxPeers = max(maxPeers, 0); len(internal) > maxPeers {
		internal, s.PeersTruncated = internal[:maxPeers], true
	}
	s.Peers = make([]TCPPeer, 0, len(internal))
	for _, r := range internal {
		s.Peers = append(s.Peers, TCPPeer{
			Address: r.key.addr.String(), Port: int(r.key.port), Direction: r.key.dir, Count: r.count,
		})
	}
	return s
}

// netnsPeerIsInternal — набор isInternalIP (threat.go) плюс 100.64/10.
//
// isInternalIP решает разбор угроз и потому не меняется; 100.64/10 (RFC 6598 —
// оверлейные сети вроде Tailscale, CGNAT провайдера) нужен атрибуции связей
// системы (решение 4) и добавлен здесь. Набор обязан совпасть с
// isInternalAddress контракта: пир, который платформа сочтёт публичным,
// отвергает всю секцию.
func netnsPeerIsInternal(addr netip.Addr) bool {
	return isInternalIP(addr.String()) || netnsSharedAddressSpace.Contains(addr.Unmap())
}

var netnsSharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// tcpScanFile добавляет LISTEN-порты и ESTABLISHED-соединения одного файла.
// Непонятные строки (включая заголовок) пропускаются: соединение, которое не
// удалось разобрать, просто не попадает в счёт и никому не приписывается.
func tcpScanFile(path string, listen map[uint16]bool, established *[]tcpSocket) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		state := fields[3]
		if state != tcpStateEstablished && state != tcpStateListen {
			continue
		}
		local, ok := tcpParseEndpoint(fields[1])
		if !ok {
			continue
		}
		if state == tcpStateListen {
			listen[local.Port()] = true
			continue
		}
		remote, ok := tcpParseEndpoint(fields[2])
		if !ok {
			continue
		}
		*established = append(*established, tcpSocket{local: local, remote: remote})
	}
	return sc.Err()
}

// tcpParseEndpoint разбирает «ADDR:PORT» из /proc/net/tcp{,6}.
//
// Ядро печатает адрес 32-битными словами (одно у IPv4, четыре у IPv6), каждое
// — в порядке байтов машины, поэтому байты слова переставляются обратно через
// NativeEndian. Агент собирается под amd64 и arm64
// (scripts/build-deploy-agent.sh), на обоих это little-endian. Порт — в
// порядке хоста, обычным числом.
func tcpParseEndpoint(s string) (netip.AddrPort, bool) {
	addrHex, portHex, found := strings.Cut(s, ":")
	if !found || len(portHex) != 4 || (len(addrHex) != 8 && len(addrHex) != 32) {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var b [16]byte
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(b[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	var addr netip.Addr
	if len(raw) == 4 {
		addr = netip.AddrFrom4([4]byte(b[:4]))
	} else {
		// ::ffff:a.b.c.d — IPv4-соединение двухстекового сокета. Без Unmap
		// один и тот же пир жил бы в ключе группировки под двумя именами.
		addr = netip.AddrFrom16(b).Unmap()
	}
	return netip.AddrPortFrom(addr, uint16(port)), true
}
