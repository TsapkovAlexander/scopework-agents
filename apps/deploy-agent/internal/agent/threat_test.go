package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClassifyThreatPath(t *testing.T) {
	if got := classifyThreatPath("/.env", 404); got != "env_probe" {
		t.Fatalf("env_probe: got %q", got)
	}
	if got := classifyThreatPath("/admin/login", 401); got != "auth_brute" {
		t.Fatalf("auth_brute: got %q", got)
	}
	if got := classifyThreatPath("/api/publish/verify-password", 429); got != "rate_limited" {
		t.Fatalf("rate_limited: got %q", got)
	}
	if got := classifyThreatPath("/api/health", 429); got != "" {
		t.Fatalf("non-auth 429: got %q", got)
	}
	if got := classifyThreatPath("/random", 404); got != "api_fuzz" {
		t.Fatalf("api_fuzz: got %q", got)
	}
}

func TestClassifyThreatPathMatchesSegmentsNotSubstrings(t *testing.T) {
	// Подстрочный матч записывал в брутфорс легитимные 401/403 на обычных путях.
	notAuth := []string{
		"/api/products/authentic-goods",
		"/blog/administrative-reform",
		"/api/tokens-usage",
	}
	for _, p := range notAuth {
		if got := classifyThreatPath(p, 403); got != "" {
			t.Fatalf("%s не auth-путь, got %q", p, got)
		}
	}

	auth := []string{"/login", "/api/auth/callback", "/admin", "/api/publish/verify-password"}
	for _, p := range auth {
		if got := classifyThreatPath(p, 401); got != "auth_brute" {
			t.Fatalf("%s — auth-путь, got %q", p, got)
		}
	}
}

func TestClassifyThreatPathIgnoresQuery(t *testing.T) {
	if got := classifyThreatPath("/reset-password?token=SECRET", 401); got != "auth_brute" {
		t.Fatalf("query не должна мешать классификации: got %q", got)
	}
	if got := classifyThreatPath("/api/products?filter=login", 403); got != "" {
		t.Fatalf("login в query — не auth-путь: got %q", got)
	}
}

// hit — запрос без размера и типа ответа: так выглядит строка любого лога, где
// этих полей нет.
func hit(ip, path string, status int) accessRecord {
	return accessRecord{RemoteIP: ip, Path: path, Status: status}
}

func TestNoteAccessStripsSecretsFromPath(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(hit("203.0.113.9", "/reset-password?token=SECRET123", 401), acc)
	tw.finalize(acc)

	for _, p := range tw.TopPaths {
		if p.Path != "/reset-password" {
			t.Fatalf("секрет из query осел в top_paths: %q", p.Path)
		}
	}
	for _, s := range tw.Samples {
		if s.Path != "/reset-password" {
			t.Fatalf("секрет из query осел в samples: %q", s.Path)
		}
	}
	for _, a := range tw.AuthAttempts {
		if a.Path != "/reset-password" {
			t.Fatalf("секрет из query осел в auth_attempts: %q", a.Path)
		}
	}
}

func TestWindowSecondsSince(t *testing.T) {
	cases := []struct {
		name      string
		prev, now int64
		want      int
	}{
		{"курсор без метки времени", 0, 1000, defaultThreatWindowSec},
		{"часы прыгнули назад", 2000, 1000, defaultThreatWindowSec},
		{"обычный тик", 1000, 1180, 180},
		{"слишком короткий интервал клампится", 1000, 1010, minThreatWindowSec},
		{"неделя простоя клампится", 1000, 1000 + 7*86400, maxThreatWindowSec},
	}
	for _, c := range cases {
		if got := windowSecondsSince(c.prev, c.now); got != c.want {
			t.Fatalf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCollectTrafficSkipsThreatsOnFirstCycle(t *testing.T) {
	// Первый запуск читает access.json с начала — там может лежать суточная
	// история. Отдать её как окно в 180 секунд значило бы гарантированный
	// ложный алерт сразу после установки агента.
	p := trafficPaths(t)
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString(accessLine("app.example.com", "/admin/login", "203.0.113.9", 401, 10))
	}
	appendLog(t, p, b.String())

	items, threat, _, err := CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if threat != nil {
		t.Fatalf("первый цикл обязан молчать по угрозам, got %+v", threat.Totals)
	}
	if len(items) == 0 {
		t.Fatal("трафик при этом собираться должен")
	}

	// Второй цикл — курсор уже есть, угрозы считаются штатно.
	appendLog(t, p, accessLine("app.example.com", "/admin/login", "203.0.113.9", 401, 10))
	_, threat, _, err = CollectTraffic(p)
	if err != nil {
		t.Fatal(err)
	}
	if threat == nil || threat.Categories["auth_brute"] != 1 {
		t.Fatalf("второй цикл обязан посчитать угрозу, got %+v", threat)
	}
	if threat.WindowSec < minThreatWindowSec {
		t.Fatalf("window_sec обязан быть в допустимом диапазоне, got %d", threat.WindowSec)
	}
}

type classifyCase struct {
	Name      string  `json:"name"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	UserAgent string  `json:"userAgent"`
	Category  *string `json:"category"`
}

// Общая фикстура с TS (classify.ts) и awk (monitor-push.sh): правила уже
// расходились молча между тремя реализациями, теперь дрейф ломает CI.
func TestClassifyMatchesSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../../packages/threat-analytics/fixtures/classify-cases.json")
	if err != nil {
		t.Fatalf("фикстура недоступна: %v", err)
	}
	var fixture struct {
		Cases []classifyCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 20 {
		t.Fatalf("фикстура подозрительно мала: %d случаев", len(fixture.Cases))
	}

	for _, c := range fixture.Cases {
		want := ""
		if c.Category != nil {
			want = *c.Category
		}
		if got := classifyThreatLine(c.Path, c.Status, c.UserAgent); got != want {
			t.Errorf("%s: Go дал %q, точка правды — %q", c.Name, got, want)
		}
	}
}

func TestNoteAccessCountsAllRequestsForTopTalker(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for i := 0; i < 12; i++ {
		tw.noteRequest(hit("203.0.113.9", "/", 200), acc)
	}
	tw.noteRequest(hit("198.51.100.7", "/", 200), acc)
	tw.finalize(acc)

	if tw.Totals.Suspicious != 0 {
		t.Fatalf("категорий сработать не должно, got %d", tw.Totals.Suspicious)
	}
	if tw.TopTalker == nil || tw.TopTalker.IP != "203.0.113.9" || tw.TopTalker.Requests != 12 {
		t.Fatalf("объёмная атака обязана быть видна, got %+v", tw.TopTalker)
	}
}

func TestNoteAccessDedupesRepeated404(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for i := 0; i < 8; i++ {
		tw.noteRequest(hit("203.0.113.9", "/old-page", 404), acc)
	}
	tw.noteRequest(hit("203.0.113.9", "/another-missing", 404), acc)
	tw.finalize(acc)

	if tw.Categories["api_fuzz"] != 2 {
		t.Fatalf("два уникальных пути, а не девять запросов: got %d", tw.Categories["api_fuzz"])
	}
}

func TestNoteAccessIgnoresStatic404(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(hit("203.0.113.9", "/assets/logo.png", 404), acc)
	tw.finalize(acc)

	if tw.Totals.Suspicious != 0 {
		t.Fatalf("битая картинка — не перебор путей, got %d", tw.Totals.Suspicious)
	}
}

func TestTopTalkerIgnoresInternalAddresses(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for i := 0; i < 20; i++ {
		tw.noteRequest(hit("172.19.0.5", "/", 200), acc)
	}
	tw.noteRequest(hit("203.0.113.9", "/", 200), acc)
	tw.finalize(acc)

	if tw.TopTalker == nil || tw.TopTalker.IP != "203.0.113.9" {
		t.Fatalf("внутренний адрес не должен быть top_talker, got %+v", tw.TopTalker)
	}
}

// --------------------------------------------------------------------------
// Факты исхода (ADR-0060 §3): отказали ли, отдали ли, долбят ли один путь
// --------------------------------------------------------------------------
//
// Судья на платформе отвечает на вопрос «получил ли сканер что-нибудь» только
// по этим полям: сырой лог хост не покидает, а десять образцов не говорят, чем
// кончились остальные три тысячи проб.

func int64p(v int64) *int64 { return &v }
func strp(v string) *string { return &v }
func probe(path string, status int) accessRecord {
	return hit("203.0.113.9", path, status)
}

func TestProbeOutcomesByStatus(t *testing.T) {
	cases := []struct {
		status int
		want   ThreatProbeOutcomes
	}{
		{200, ThreatProbeOutcomes{Served: 1}},
		{206, ThreatProbeOutcomes{Served: 1}},
		{301, ThreatProbeOutcomes{Redirected: 1}},
		{307, ThreatProbeOutcomes{Redirected: 1}},
		{500, ThreatProbeOutcomes{Failed: 1}},
		{503, ThreatProbeOutcomes{Failed: 1}},
		{403, ThreatProbeOutcomes{Refused: 1}},
		{404, ThreatProbeOutcomes{Refused: 1}},
		{429, ThreatProbeOutcomes{Refused: 1}},
		{444, ThreatProbeOutcomes{Refused: 1}},
		{499, ThreatProbeOutcomes{Refused: 1}},
		// Caddy пишет 0, когда соединение оборвано `abort` — ответа не было вовсе.
		{0, ThreatProbeOutcomes{Refused: 1}},
		// Неизвестное — отказ: «отдано» без 2xx было бы выдумкой.
		{101, ThreatProbeOutcomes{Refused: 1}},
	}
	for _, c := range cases {
		tw, acc := newThreatAccumulator(false)
		tw.noteRequest(probe("/.env", c.status), acc)
		tw.finalize(acc)
		if tw.ProbeOutcomes != c.want {
			t.Errorf("статус %d: исход %+v, ожидался %+v", c.status, tw.ProbeOutcomes, c.want)
		}
	}
}

// Проба определяется свойством пути, а не категорией. Категория отвечает на
// вопрос «кто это», исход — «что он получил»: сканер, назвавшийся zgrab,
// получает категорию scanner_ua, и прежний учёт по категории терял его
// единственный ответ 200 на `/backup.sql`.
func TestProbeOutcomesByPathNotCategory(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(probe("/wp-login.php", 200), acc)
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/backup.sql", Status: 200,
		UserAgent: "Mozilla/5.0 zgrab/0.x"}, acc)
	// Повтор 404 с того же адреса схлопывается в api_fuzz, но проба остаётся
	// пробой: отказ получил каждый запрос.
	tw.noteRequest(probe("/.capistrano", 404), acc)
	tw.noteRequest(probe("/.capistrano", 404), acc)
	tw.noteRequest(probe("/.gitignore", 404), acc)
	tw.noteRequest(probe("/users.db/", 404), acc) // слэш в конце — тот же файл
	// Не пробы: обычные страницы, вход, законный `.well-known` на любой глубине
	// и собственный краулер платформы.
	tw.noteRequest(probe("/", 200), acc)
	tw.noteRequest(probe("/login", 401), acc)
	tw.noteRequest(probe("/missing", 404), acc)
	tw.noteRequest(probe("/.well-known/security.txt", 200), acc)
	tw.noteRequest(probe("/auth/v1/.well-known/jwks.json", 200), acc)
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.env", Status: 200,
		UserAgent: "ScopeworkSiteAuditBot/1.0"}, acc)
	tw.finalize(acc)

	if want := (ThreatProbeOutcomes{Served: 2, Refused: 4}); tw.ProbeOutcomes != want {
		t.Fatalf("исход проб %+v, ожидался %+v", tw.ProbeOutcomes, want)
	}
}

// Отданным секретом считается только явный список имён, а не любой сегмент с
// точкой. `.github`, `.gitignore`, `.NET-portal.zip` в объектах Storage — законные
// ответы приложений клиентов; попади они в served_probes, судья будил бы
// человека тревогой «отдан файл» на каждый заход в Gitea.
func TestSecretPathIsExplicitList(t *testing.T) {
	for _, p := range []string{
		"/.env", "/.env.local", "/.env_copy", "/repo/.env", "/.git/config", "/a/.ssh/id_rsa",
		"/.git-credentials", "/wp-config.php.bak", "/actuator/env", "/actuator/heapdump",
		"/actuator/configprops", "/backup.sql", "/users.db/", "/.vault-token",
	} {
		if !isProbePath(p) || !isSecretPath(p) {
			t.Errorf("%s обязан быть пробой и секретом: probe=%v secret=%v", p, isProbePath(p), isSecretPath(p))
		}
	}
	// Пробы, но не секреты: исход считается, в список отданного не попадают.
	for _, p := range []string{
		"/.gitignore", "/.environment-notes", "/o/r/src/.github/workflows/ci.yml",
		"/storage/v1/object/public/b/.net-portal.zip", "/actuator/health", "/wp-login.php",
		"/blog/wp-admin/setup-config.php",
	} {
		if !isProbePath(p) || isSecretPath(p) {
			t.Errorf("%s — проба, но не секрет: probe=%v secret=%v", p, isProbePath(p), isSecretPath(p))
		}
	}
	for _, p := range []string{
		"/", "/api/users", "/.well-known/acme-challenge/x", "/auth/v1/.well-known/jwks.json",
		"/assets/app.js", "/export.csv",
	} {
		if isProbePath(p) || isSecretPath(p) {
			t.Errorf("%s не проба: probe=%v secret=%v", p, isProbePath(p), isSecretPath(p))
		}
	}
}

func TestServedProbesOnePerPathInFirstSeenOrder(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.git/config", Status: 200,
		Bytes: int64p(318), ContentType: "text/plain"}, acc)
	tw.noteRequest(probe("/.env", 404), acc) // отказ — не отдано
	// Тот же путь с query — тот же путь: секрет из ссылки не должен уехать,
	// а повтор не должен занять второе место из десяти.
	tw.noteRequest(accessRecord{RemoteIP: "198.51.100.7", Path: "/.env?x=SECRET", Status: 200,
		Bytes: int64p(412)}, acc)
	tw.finalize(acc)

	want := []ThreatServedProbe{
		{Path: "/.git/config", Status: 200, Bytes: int64p(318), ContentType: strp("text/plain")},
		{Path: "/.env", Status: 200, Bytes: int64p(412), ContentType: nil},
	}
	if !reflect.DeepEqual(tw.ServedProbes, want) {
		t.Fatalf("served_probes:\n got %s\nwant %s", mustJSON(t, tw.ServedProbes), mustJSON(t, want))
	}
}

// Повтор пути сводит факты, а не теряет их. HEAD отдаёт 0 байт без типа, и
// если бы первый ответ был окончательным, настоящий файл, отданный следом
// GET-ом, выглядел бы пустым ответом.
func TestServedProbesRepeatMergesFacts(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.env", Status: 200, Bytes: int64p(0)}, acc)
	// HTML-ответ того же пути запись не меняет вовсе — ни тип, ни размер: это
	// страница приложения, и её 300 байт не делают файл трёхсотбайтным.
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.env", Status: 200,
		Bytes: int64p(300), ContentType: "Text/HTML; charset=utf-8"}, acc)
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.env", Status: 200,
		Bytes: int64p(120), ContentType: "text/plain"}, acc)
	tw.finalize(acc)

	want := []ThreatServedProbe{{Path: "/.env", Status: 200, Bytes: int64p(120), ContentType: strp("text/plain")}}
	if !reflect.DeepEqual(tw.ServedProbes, want) {
		t.Fatalf("served_probes:\n got %s\nwant %s", mustJSON(t, tw.ServedProbes), mustJSON(t, want))
	}
}

// HTML-ответ места в списке не занимает — ни на первом появлении пути, ни
// регистром типа. Иначе десяток отрисованных страниц 404-с-кодом-200
// вытеснил бы настоящий файл, отданный одиннадцатым.
func TestServedProbesSkipHTML(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for i := 0; i < 12; i++ {
		tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: fmt.Sprintf("/.env.v%d", i), Status: 200,
			Bytes: int64p(int64(1000 + i)), ContentType: "TEXT/HTML"}, acc)
	}
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.git/config", Status: 200,
		Bytes: int64p(312), ContentType: "text/plain"}, acc)
	tw.finalize(acc)

	if len(tw.ServedProbes) != 1 || tw.ServedProbes[0].Path != "/.git/config" {
		t.Fatalf("HTML занял место в served_probes: %s", mustJSON(t, tw.ServedProbes))
	}
	if tw.ProbeOutcomes.Served != 13 {
		t.Fatalf("в исходе HTML обязан считаться отданным: %+v", tw.ProbeOutcomes)
	}
}

// Одинаковый размер у многих проб — общая заглушка приложения; держать её в
// списке десятью копиями значило бы вытеснить настоящий ответ. Три — ровно
// столько, сколько судье нужно, чтобы опознать заглушку.
func TestServedProbesAtMostThreeWithSameBytes(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for _, p := range []string{"/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa", "/.htpasswd"} {
		tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: p, Status: 200, Bytes: int64p(1832)}, acc)
	}
	// Неизвестный размер пределом не режется: одинаковым он не бывает.
	for _, p := range []string{"/.npmrc", "/.pgpass", "/.netrc", "/.s3cfg"} {
		tw.noteRequest(probe(p, 200), acc)
	}
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.kube/config", Status: 200, Bytes: int64p(77)}, acc)
	tw.finalize(acc)

	var got []string
	for _, p := range tw.ServedProbes {
		got = append(got, p.Path)
	}
	want := []string{"/.env", "/.git/config", "/.aws/credentials", "/.npmrc", "/.pgpass", "/.netrc", "/.s3cfg", "/.kube/config"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("served_probes %v, ожидалось %v", got, want)
	}
}

func TestServedProbesCappedAtTen(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for i := 0; i < 15; i++ {
		tw.noteRequest(probe(fmt.Sprintf("/.env.%d", i), 200), acc)
	}
	tw.finalize(acc)

	if len(tw.ServedProbes) != 10 {
		t.Fatalf("отдано проб %d, предел 10", len(tw.ServedProbes))
	}
	if tw.ServedProbes[9].Path != "/.env.9" {
		t.Fatalf("предел срезал не хвост, а начало: %+v", tw.ServedProbes[9])
	}
	// Счётчик исхода пределом не режется: «отдано 15» и «показаны 10» — разные числа.
	if tw.ProbeOutcomes.Served != 15 {
		t.Fatalf("served %d, ожидалось 15", tw.ProbeOutcomes.Served)
	}
}

// Тип содержимого — строка чужого приложения. Режем по символам, а не по
// байтам: разрез посередине UTF-8 дал бы невалидную строку в JSON. Резать, а не
// обнулять: судья читает тип по началу строки, и обнулённый длинный тип
// превратился бы в «ответ без типа» — другую тревогу на ровном месте.
func TestServedProbeContentTypeBounded(t *testing.T) {
	long := "application/octet-stream; name=" + strings.Repeat("ж", 200)
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(accessRecord{RemoteIP: "203.0.113.9", Path: "/.env", Status: 200, ContentType: long}, acc)
	tw.finalize(acc)

	got := tw.ServedProbes[0].ContentType
	if got == nil || utf8.RuneCountInString(*got) != 100 || !utf8.ValidString(*got) {
		t.Fatalf("content_type не приведён к 100 символам: %v", got)
	}
	if !strings.HasPrefix(*got, "application/octet-stream") {
		t.Fatalf("начало типа потеряно: %q", *got)
	}
}

// Сумма по пути по всем адресам (поправка В): распределённый подбор — шестьдесят
// адресов по девять попыток — не набирает концентрации ни на одной паре, и
// виден только здесь.
func TestAuthPathsAggregateAcrossAddresses(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	add := func(ip, path string, n int) {
		for i := 0; i < n; i++ {
			tw.noteRequest(hit(ip, path, 401), acc)
		}
	}
	add("203.0.113.1", "/login", 2)
	add("203.0.113.2", "/login", 3)
	add("203.0.113.3", "/login", 4)
	add("203.0.113.1", "/admin", 9)
	add("203.0.113.1", "/session", 1)
	add("203.0.113.1", "/auth", 1)  // равный счёт — по пути
	add("203.0.113.2", "/token", 1) // шестой путь — за пределом
	add("203.0.113.3", "/sign-in", 1)
	tw.finalize(acc)

	want := []ThreatAuthPath{
		{Path: "/admin", Count: 9, IPs: 1},
		{Path: "/login", Count: 9, IPs: 3},
		{Path: "/auth", Count: 1, IPs: 1},
		{Path: "/session", Count: 1, IPs: 1},
		{Path: "/sign-in", Count: 1, IPs: 1},
	}
	if !reflect.DeepEqual(tw.AuthPaths, want) {
		t.Fatalf("auth_paths:\n got %s\nwant %s", mustJSON(t, tw.AuthPaths), mustJSON(t, want))
	}
}

// Пары (адрес, путь) — основа правила «подбор — это концентрация» (§5).
func TestAuthAttemptsSortedAndCapped(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	add := func(ip, path string, status, n int) {
		for i := 0; i < n; i++ {
			tw.noteRequest(hit(ip, path, status), acc)
		}
	}
	add("203.0.113.9", "/login", 401, 3)
	add("203.0.113.1", "/login", 401, 3)        // равный счёт: при том же пути — по адресу
	add("203.0.113.9", "/api/auth/x", 429, 3)   // равный счёт: путь раньше по алфавиту
	add("203.0.113.9", "/admin?next=/", 403, 7) // query не создаёт отдельной пары
	add("203.0.113.9", "/session", 401, 1)
	add("203.0.113.9", "/token", 401, 1)      // шестая пара — за пределом
	add("203.0.113.9", "/login/.env", 404, 9) // разведка, не вход
	tw.finalize(acc)

	want := []ThreatAuthAttempt{
		{IP: "203.0.113.9", Path: "/admin", Count: 7},
		{IP: "203.0.113.9", Path: "/api/auth/x", Count: 3},
		{IP: "203.0.113.1", Path: "/login", Count: 3},
		{IP: "203.0.113.9", Path: "/login", Count: 3},
		{IP: "203.0.113.9", Path: "/session", Count: 1},
	}
	if !reflect.DeepEqual(tw.AuthAttempts, want) {
		t.Fatalf("auth_attempts:\n got %s\nwant %s", mustJSON(t, tw.AuthAttempts), mustJSON(t, want))
	}
}

// Словарь пар ограничен, как и остальные словари сбора: пятьдесят тысяч строк
// с разными путями иначе держали бы в памяти агента пятьдесят тысяч ключей
// до полукилобайта каждый. Упёршись в предел, сбор честно говорит об усечении.
func TestAuthPairsBoundedWithTruncation(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	for i := 0; i < maxAuthPairs; i++ {
		tw.noteRequest(hit("203.0.113.9", fmt.Sprintf("/login/%d", i), 401), acc)
	}
	if tw.Truncated {
		t.Fatal("усечение объявлено до предела")
	}
	tw.noteRequest(hit("203.0.113.9", "/login/overflow", 401), acc)
	// Уже известная пара продолжает считаться и за пределом: подбор, начатый до
	// переполнения, не должен исчезнуть из-за постороннего шума.
	tw.noteRequest(hit("203.0.113.9", "/login/0", 401), acc)
	tw.finalize(acc)

	if len(acc.authPairs) != maxAuthPairs {
		t.Fatalf("пар в памяти %d, предел %d", len(acc.authPairs), maxAuthPairs)
	}
	if !tw.Truncated {
		t.Fatal("переполнение словаря пар не помечено усечением")
	}
	if tw.AuthAttempts[0].Path != "/login/0" || tw.AuthAttempts[0].Count != 2 {
		t.Fatalf("известная пара перестала считаться за пределом: %+v", tw.AuthAttempts[0])
	}
}

// `auth_attempts: []` — признак агента v2. Пропуск поля или null платформа
// прочитала бы как агента v1 и судила бы подбор по старым суммам.
func TestThreatWindowV2WireFormat(t *testing.T) {
	tw, acc := newThreatAccumulator(false)
	tw.noteRequest(probe("/.env", 200), acc)
	tw.finalize(acc)
	raw := mustJSON(t, tw)

	for _, want := range []string{
		`"schema_version":2`,
		`"probe_outcomes":{"refused":0,"redirected":0,"served":1,"failed":0}`,
		`"served_probes":[{"path":"/.env","status":200,"bytes":null,"content_type":null}]`,
		`"auth_attempts":[]`,
		`"auth_paths":[]`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("нет %s в %s", want, raw)
		}
	}

	empty, emptyAcc := newThreatAccumulator(false)
	empty.finalize(emptyAcc)
	raw = mustJSON(t, empty)
	for _, want := range []string{`"served_probes":[]`, `"auth_attempts":[]`, `"auth_paths":[]`} {
		if !strings.Contains(raw, want) {
			t.Errorf("пустые факты обязаны уходить пустыми массивами, нет %s: %s", want, raw)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// --------------------------------------------------------------------------
// Оконная фикстура: те же агрегаты, что у awk и у судьи
// --------------------------------------------------------------------------

type windowRecord struct {
	IP          string  `json:"ip"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	Status      int     `json:"status"`
	Bytes       *int64  `json:"bytes"`
	Host        string  `json:"host"`
	UserAgent   string  `json:"userAgent"`
	ContentType *string `json:"contentType"`
	Repeat      int     `json:"repeat"`
}

type windowExpect struct {
	Parsed        int64               `json:"parsed"`
	Suspicious    int64               `json:"suspicious"`
	Categories    map[string]int64    `json:"categories"`
	TopIPs        []ThreatTopIP       `json:"top_ips"`
	ProbeOutcomes ThreatProbeOutcomes `json:"probe_outcomes"`
	ServedProbes  []ThreatServedProbe `json:"served_probes"`
	AuthAttempts  []ThreatAuthAttempt `json:"auth_attempts"`
	AuthPaths     []ThreatAuthPath    `json:"auth_paths"`
	TopTalker     *ThreatTopTalker    `json:"top_talker"`
}

// caddyFixtureLine рендерит запись фикстуры в строку access-лога Caddy той
// формы, что пишет боевой Caddy: с полями, которых агент не читает, — иначе
// тест не заметил бы, что разбор споткнулся о настоящий формат.
func caddyFixtureLine(t *testing.T, r windowRecord) string {
	t.Helper()
	headers := map[string][]string{"Accept": {"*/*"}}
	// «-» — так nginx пишет отсутствующий заголовок. У Caddy заголовка
	// в таком запросе нет вовсе.
	if r.UserAgent != "" && r.UserAgent != "-" {
		headers["User-Agent"] = []string{r.UserAgent}
	}
	resp := map[string][]string{"Server": {"Caddy"}}
	if r.ContentType != nil {
		resp["Content-Type"] = []string{*r.ContentType}
	}
	size := int64(0)
	if r.Bytes != nil {
		size = *r.Bytes
	}
	line := map[string]any{
		"level":  "info",
		"ts":     1757543851.123,
		"logger": "http.log.access.log0",
		"msg":    "handled request",
		"request": map[string]any{
			"remote_ip":   r.IP,
			"remote_port": "51234",
			"client_ip":   r.IP,
			"proto":       "HTTP/1.1",
			"method":      r.Method,
			"host":        r.Host,
			"uri":         r.Path,
			"headers":     headers,
		},
		"bytes_read":   0,
		"user_id":      "",
		"duration":     0.0012,
		"size":         size,
		"status":       r.Status,
		"resp_headers": resp,
	}
	raw, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw) + "\n"
}

// Прогон идёт через CollectTraffic — тот же путь, что у боевого сбора: разбор
// строки Caddy, фильтр по Host, аккумулятор и finalize. Проверка одного
// аккумулятора не поймала бы, что строка с голым адресом в Host выброшена ещё
// до учёта угроз, — а именно так сканеры по IP и были невидимы.
func TestWindowMatchesSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../../packages/threat-analytics/fixtures/window-cases.json")
	if err != nil {
		t.Fatalf("фикстура недоступна: %v", err)
	}
	var fixture struct {
		Cases []struct {
			Name    string         `json:"name"`
			Records []windowRecord `json:"records"`
			Expect  windowExpect   `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 5 {
		t.Fatalf("фикстура подозрительно мала: %d случаев", len(fixture.Cases))
	}

	// Журнал SSH хоста в окно подмешиваться не должен: тест обязан давать один
	// ответ на любой машине.
	savedSSH := sshAuthLogPaths
	sshAuthLogPaths = []string{filepath.Join(t.TempDir(), "нет-журнала")}
	defer func() { sshAuthLogPaths = savedSSH }()

	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			want := c.Expect

			p := trafficPaths(t)
			// Первый сбор только знакомится с файлом и угроз не отдаёт.
			appendLog(t, p, accessLine("bootstrap.example.test", "/", "192.0.2.1", 200, 1))
			if _, threat, _, err := CollectTraffic(p); err != nil || threat != nil {
				t.Fatalf("знакомство с логом: threat=%v err=%v", threat, err)
			}

			var b strings.Builder
			for _, r := range c.Records {
				n := r.Repeat
				if n == 0 {
					n = 1
				}
				line := caddyFixtureLine(t, r)
				for i := 0; i < n; i++ {
					b.WriteString(line)
				}
			}
			appendLog(t, p, b.String())

			_, got, _, err := CollectTraffic(p)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatal("окно угроз не собрано")
			}

			if got.Totals.Parsed != want.Parsed {
				t.Errorf("parsed %d, ожидалось %d", got.Totals.Parsed, want.Parsed)
			}
			if got.Totals.Suspicious != want.Suspicious {
				t.Errorf("suspicious %d, ожидалось %d", got.Totals.Suspicious, want.Suspicious)
			}
			if !reflect.DeepEqual(got.Categories, want.Categories) {
				t.Errorf("categories %v, ожидалось %v", got.Categories, want.Categories)
			}
			if got.ProbeOutcomes != want.ProbeOutcomes {
				t.Errorf("probe_outcomes %+v, ожидалось %+v", got.ProbeOutcomes, want.ProbeOutcomes)
			}
			if !reflect.DeepEqual(got.ServedProbes, want.ServedProbes) {
				t.Errorf("served_probes\n got %s\nwant %s", mustJSON(t, got.ServedProbes), mustJSON(t, want.ServedProbes))
			}
			// Порядок пар задан контрактом целиком, поэтому сверяется весь
			// список, а не только наибольший счёт.
			if !reflect.DeepEqual(got.AuthAttempts, want.AuthAttempts) {
				t.Errorf("auth_attempts\n got %s\nwant %s", mustJSON(t, got.AuthAttempts), mustJSON(t, want.AuthAttempts))
			}
			if want.AuthPaths == nil {
				t.Fatal("в случае фикстуры нет auth_paths — сверять нечего")
			}
			if !reflect.DeepEqual(got.AuthPaths, want.AuthPaths) {
				t.Errorf("auth_paths\n got %s\nwant %s", mustJSON(t, got.AuthPaths), mustJSON(t, want.AuthPaths))
			}
			if len(want.TopIPs) == 0 {
				if len(got.TopIPs) != 0 {
					t.Errorf("top_ips %+v, ожидался пустой", got.TopIPs)
				}
			} else if len(got.TopIPs) == 0 || got.TopIPs[0].IP != want.TopIPs[0].IP || got.TopIPs[0].Count != want.TopIPs[0].Count {
				t.Errorf("top_ips[0] %+v, ожидалось %+v", got.TopIPs, want.TopIPs[0])
			}
			if !reflect.DeepEqual(got.TopTalker, want.TopTalker) {
				t.Errorf("top_talker %+v, ожидалось %+v", got.TopTalker, want.TopTalker)
			}
		})
	}
}

// Те же случаи, что у isBackgroundRequest в classify.test.ts.
func TestIsBackgroundRequest(t *testing.T) {
	cases := []struct {
		path   string
		status int
		want   bool
	}{
		{"/dashboard?_rsc=1x9ab", 200, true},
		{"/calendar?from=2026-09-01&_rsc=abc", 200, true},
		{"/dashboard?_rsc=1x9ab", 404, true},
		{"/dashboard?x_rsc=1", 200, false},
		{"/_rsc=1/dashboard", 200, false},
		{"/logo.svg", 304, true},
		{"/_next/static/chunks/main-app.js?v=1", 304, true},
		{"/manifest.webmanifest", 304, true},
		{"/logo.svg", 200, false},
		{"/dashboard", 304, false},
	}
	for _, c := range cases {
		if got := isBackgroundRequest(c.path, c.status); got != c.want {
			t.Errorf("isBackgroundRequest(%q, %d) = %v, ожидалось %v", c.path, c.status, got, c.want)
		}
	}
}
