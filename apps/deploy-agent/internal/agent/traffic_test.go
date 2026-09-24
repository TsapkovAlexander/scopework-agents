package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Сбор агрегатов access-лога: инкрементальность, ротация, устойчивость к
// мусору. Сырые строки хост не покидают — проверяем только агрегаты.

func trafficPaths(t *testing.T) Paths {
	t.Helper()
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(p.proxyDir(), "logs"), 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

func accessLine(host, uri, ip string, status, size int) string {
	return fmt.Sprintf(
		`{"logger":"http.log.access.log0","status":%d,"size":%d,"request":{"host":"%s","uri":"%s","remote_ip":"%s"}}`+"\n",
		status, size, host, uri, ip)
}

func appendLog(t *testing.T, p Paths, content string) {
	t.Helper()
	f, err := os.OpenFile(p.trafficLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func TestCollectTrafficAggregates(t *testing.T) {
	p := trafficPaths(t)
	appendLog(t, p,
		accessLine("n8n.example.com", "/rest/login?next=1", "1.1.1.1", 200, 100)+
			accessLine("n8n.example.com", "/rest/login", "1.1.1.1", 401, 50)+
			accessLine("n8n.example.com", "/health", "2.2.2.2", 500, 10)+
			accessLine("site.example.com", "/", "3.3.3.3", 301, 0))

	items, _, truncated, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("выборка помечена усечённой без причины")
	}
	if len(items) != 2 {
		t.Fatalf("доменов %d, ожидалось 2: %+v", len(items), items)
	}

	n8n := items[0]
	if n8n.Domain != "n8n.example.com" || n8n.Requests != 3 || n8n.BytesOut != 160 {
		t.Fatalf("агрегат n8n неверен: %+v", n8n)
	}
	if n8n.Status2xx != 1 || n8n.Status4xx != 1 || n8n.Status5xx != 1 {
		t.Fatalf("классы статусов неверны: %+v", n8n)
	}
	if n8n.UniqueIPs != 2 {
		t.Fatalf("уникальных адресов %d, ожидалось 2", n8n.UniqueIPs)
	}
	// Query отрезан: /rest/login?next=1 и /rest/login — один путь.
	if len(n8n.TopPaths) != 2 || n8n.TopPaths[0].Path != "/rest/login" || n8n.TopPaths[0].Count != 2 {
		t.Fatalf("топ путей неверен: %+v", n8n.TopPaths)
	}
}

func TestCollectTrafficIsIncremental(t *testing.T) {
	p := trafficPaths(t)
	appendLog(t, p, accessLine("a.example.com", "/", "1.1.1.1", 200, 1))

	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}

	// Второй сбор без новых строк — пусто, а не повторный счёт.
	items, _, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("повторный счёт уже прочитанного: %+v", items)
	}

	appendLog(t, p, accessLine("a.example.com", "/new", "1.1.1.1", 200, 5))
	items, _, _, err = CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Requests != 1 || items[0].TopPaths[0].Path != "/new" {
		t.Fatalf("прочитан не только новый хвост: %+v", items)
	}
}

func TestCollectTrafficSurvivesRotation(t *testing.T) {
	p := trafficPaths(t)
	appendLog(t, p, accessLine("a.example.com", "/", "1.1.1.1", 200, 1))
	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}

	// Ротация: файл пересоздан, inode другой — читаем с начала нового файла.
	if err := os.Remove(p.trafficLogPath()); err != nil {
		t.Fatal(err)
	}
	appendLog(t, p, accessLine("a.example.com", "/after-rotate", "1.1.1.1", 200, 2))

	items, _, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].TopPaths[0].Path != "/after-rotate" {
		t.Fatalf("после ротации хвост потерян: %+v", items)
	}
}

func TestCollectTrafficSkipsGarbage(t *testing.T) {
	p := trafficPaths(t)
	appendLog(t, p,
		"это не json\n"+
			`{"logger":"http.log.access","status":200,"size":1,"request":{"host":"НЕ ДОМЕН","uri":"/","remote_ip":"1.1.1.1"}}`+"\n"+
			accessLine("ok.example.com", "/", "1.1.1.1", 200, 1)+
			// Недописанная строка без \n остаётся следующему циклу.
			`{"logger":"http.log.access","status":200`)

	items, _, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Domain != "ok.example.com" {
		t.Fatalf("мусор повлиял на агрегаты: %+v", items)
	}

	// Дописанный хвост читается следующим циклом целиком.
	appendLog(t, p, `,"size":9,"request":{"host":"ok.example.com","uri":"/tail","remote_ip":"2.2.2.2"}}`+"\n")
	items, _, _, err = CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].TopPaths[0].Path != "/tail" {
		t.Fatalf("недописанная строка потеряна: %+v", items)
	}
}

func TestCollectTrafficMissingLogIsNotAnError(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	items, _, truncated, err := CollectTraffic(p)
	if err != nil || items != nil || truncated {
		t.Fatalf("отсутствие лога должно быть тишиной: %v %v %v", items, truncated, err)
	}
}

func TestCollectTrafficCapsLines(t *testing.T) {
	p := trafficPaths(t)
	var b strings.Builder
	for i := 0; i < maxTrafficLinesPerTick+100; i++ {
		b.WriteString(accessLine("a.example.com", "/", "1.1.1.1", 200, 1))
	}
	appendLog(t, p, b.String())

	items, _, truncated, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("превышение лимита строк не помечено усечением")
	}
	if items[0].Requests != maxTrafficLinesPerTick {
		t.Fatalf("прочитано %d строк, лимит %d", items[0].Requests, maxTrafficLinesPerTick)
	}

	// Остаток дочитывается следующим циклом.
	items, _, _, err = CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Requests != 100 {
		t.Fatalf("хвост за лимитом потерян: %+v", items)
	}
}

// Угрозы считаются по ЛЮБОЙ строке лога, агрегаты трафика — только по доменам.
//
// Раньше строка с Host, не похожим на домен, выбрасывалась до учёта угроз.
// Массовый сканер ходит по адресу, без Host или с портом в нём — и такой
// сканер на кромке клиентов не существовал ни в одном счётчике, хотя его
// запросы лежали в логе. Трафику же нужен домен: агрегат по «[2001:db8::1]»
// некому показать, у него нет карточки приложения.
func TestCollectTrafficCountsThreatsForAnyHost(t *testing.T) {
	savedSSH := sshAuthLogPaths
	sshAuthLogPaths = []string{filepath.Join(t.TempDir(), "нет-журнала")}
	defer func() { sshAuthLogPaths = savedSSH }()

	p := trafficPaths(t)
	appendLog(t, p, accessLine("app.example.com", "/", "192.0.2.1", 200, 1))
	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}

	appendLog(t, p,
		accessLine("", "/.env", "203.0.113.1", 404, 10)+
			accessLine("198.51.100.10:80", "/.env", "203.0.113.2", 404, 10)+
			accessLine("[2001:db8::1]", "/.git/config", "203.0.113.3", 0, 0)+
			accessLine("app.example.com:443", "/wp-login.php", "203.0.113.4", 404, 10)+
			accessLine("app.example.com", "/", "203.0.113.4", 200, 100))

	items, threat, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if threat == nil {
		t.Fatal("окно угроз не собрано")
	}
	if threat.Totals.Parsed != 5 {
		t.Fatalf("разобрано %d строк, ожидалось 5: строки без домена потеряны", threat.Totals.Parsed)
	}
	if threat.Categories["env_probe"] != 3 || threat.Categories["cms_scan"] != 1 {
		t.Fatalf("разведка по адресу не учтена: %v", threat.Categories)
	}
	if threat.ProbeOutcomes.Refused != 4 {
		t.Fatalf("исход проб без домена не учтён: %+v", threat.ProbeOutcomes)
	}
	// Самый активный адрес считается по всем строкам: 203.0.113.4 пришёл и по
	// домену с портом, и по чистому домену.
	if threat.TopTalker == nil || threat.TopTalker.IP != "203.0.113.4" || threat.TopTalker.Requests != 2 {
		t.Fatalf("top_talker не видит строк без домена: %+v", threat.TopTalker)
	}

	if len(items) != 1 || items[0].Domain != "app.example.com" || items[0].Requests != 1 {
		t.Fatalf("агрегаты трафика обязаны остаться только у доменов: %+v", items)
	}
}

// Регрессия: ротация с ПЕРЕИСПОЛЬЗОВАНИЕМ inode. На ext4 только что
// освобождённый номер выдаётся следующему файлу, поэтому «тот же inode» не
// означает «тот же файл». Здесь худший случай воспроизведён детерминированно
// на любой ФС: файл перезаписан целиком, inode сохранён, длина больше
// прежнего смещения — то есть ни inode, ни размер подмену не выдают.
//
// До отпечатка агент отсчитывал старое смещение в новом файле и молча терял
// весь трафик до этой точки (а читал бы обрывки строк).
func TestCollectTrafficDetectsRewrittenFile(t *testing.T) {
	p := trafficPaths(t)
	appendLog(t, p, accessLine("a.example.com", "/first", "1.1.1.1", 200, 1))
	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}

	rewritten := accessLine("a.example.com", "/after-rewrite-with-longer-path", "2.2.2.2", 200, 2)
	if err := os.WriteFile(p.trafficLogPath(), []byte(rewritten), 0o640); err != nil {
		t.Fatal(err)
	}

	items, _, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Requests != 1 {
		t.Fatalf("подмена файла не обнаружена, трафик потерян: %+v", items)
	}
	if items[0].TopPaths[0].Path != "/after-rewrite-with-longer-path" {
		t.Fatalf("прочитано не содержимое нового файла: %+v", items[0].TopPaths)
	}
}

// Отпечаток снят с короткого файла, потом файл дорос: это ТОТ ЖЕ файл,
// перечитывать с начала нельзя — иначе окно посчиталось бы дважды.
func TestCollectTrafficFingerprintMaturesWithoutDoubleCount(t *testing.T) {
	p := trafficPaths(t)
	appendLog(t, p, accessLine("a.example.com", "/1", "1.1.1.1", 200, 1))
	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}

	// Дописываем много строк — файл заведомо перерастает окно отпечатка.
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString(accessLine("a.example.com", "/2", "1.1.1.1", 200, 1))
	}
	appendLog(t, p, b.String())

	items, _, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Requests != 40 {
		t.Fatalf("запросов %v, ожидалось ровно 40 (без повторного счёта первой строки)", items)
	}
}
