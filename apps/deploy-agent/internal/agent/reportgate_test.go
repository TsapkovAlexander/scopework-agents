package agent

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// Отсев одинаковых отчётов — единственная оптимизация, которая может стоить
// платформе данных: ошибка здесь выглядит как «карточка приложения показывает
// вчерашнее состояние», и заметить её по логам нельзя.

func TestGateSendsFirstTime(t *testing.T) {
	g := NewReportGate()
	now := time.Unix(1_700_000_000, 0)

	if !g.Allow("health", "abc", now, 5*time.Minute) {
		t.Fatal("первый отчёт не отправлен")
	}
}

func TestGateSkipsUnchangedUntilDeadline(t *testing.T) {
	g := NewReportGate()
	now := time.Unix(1_700_000_000, 0)
	g.Mark("health", "abc", now)

	if g.Allow("health", "abc", now.Add(time.Minute), 5*time.Minute) {
		t.Fatal("неизменившийся отчёт отправлен раньше срока")
	}
	if !g.Allow("health", "abc", now.Add(5*time.Minute), 5*time.Minute) {
		t.Fatal("срок истёк, а отчёт не отправлен: платформа сочтёт данные протухшими")
	}
}

func TestGateSendsOnChange(t *testing.T) {
	g := NewReportGate()
	now := time.Unix(1_700_000_000, 0)
	g.Mark("health", "abc", now)

	if !g.Allow("health", "изменилось", now.Add(time.Second), time.Hour) {
		t.Fatal("изменившийся отчёт задержан: падение сервиса доехало бы через час")
	}
}

// Отметка ставится только после успешной отправки. Иначе сетевой сбой
// засчитался бы как доставка, и следующая попытка не состоялась бы до срока.
func TestGateRetriesWhenNotMarked(t *testing.T) {
	g := NewReportGate()
	now := time.Unix(1_700_000_000, 0)

	if !g.Allow("presence", "abc", now, 5*time.Minute) {
		t.Fatal("первая попытка не разрешена")
	}
	// Mark не вызван — отправка не удалась.
	if !g.Allow("presence", "abc", now.Add(time.Second), 5*time.Minute) {
		t.Fatal("повтор после неудачной отправки запрещён")
	}
}

func TestGateKindsAreIndependent(t *testing.T) {
	g := NewReportGate()
	now := time.Unix(1_700_000_000, 0)
	g.Mark("health", "abc", now)

	if !g.Allow("presence", "abc", now, 5*time.Minute) {
		t.Fatal("отчёты разных видов делят одну отметку")
	}
}

func TestPayloadHashDistinguishesContent(t *testing.T) {
	a := PayloadHash([]AppHealth{{Slug: "app", Status: HealthHealthy}})
	b := PayloadHash([]AppHealth{{Slug: "app", Status: HealthDown}})
	if a == "" || b == "" {
		t.Fatal("отпечаток не посчитался")
	}
	if a == b {
		t.Fatal("разные состояния дали один отпечаток — падение не доехало бы до платформы")
	}
	if a != PayloadHash([]AppHealth{{Slug: "app", Status: HealthHealthy}}) {
		t.Fatal("отпечаток нестабилен: отчёт уходил бы каждый такт")
	}
}

// Что считается тихим окном. Порог по адресу заведомо ниже платформенного,
// поэтому ложных пропусков быть не может — только лишние отправки.
func TestThreatWorthSending(t *testing.T) {
	quiet := &ThreatWindow{}
	quiet.Totals.Parsed = 5000
	if ThreatWorthSending(quiet) {
		t.Fatal("окно без единого срабатывания признано достойным отправки")
	}

	suspicious := &ThreatWindow{}
	suspicious.Totals.Suspicious = 1
	if !ThreatWorthSending(suspicious) {
		t.Fatal("окно с подозрительным событием пропущено")
	}

	auth := &ThreatWindow{}
	auth.Totals.AuthFailures = 1
	if !ThreatWorthSending(auth) {
		t.Fatal("неудачные входы пропущены")
	}

	truncated := &ThreatWindow{Truncated: true}
	if !ThreatWorthSending(truncated) {
		t.Fatal("окно с потерянными событиями пропущено — потеря стала бы невидимой")
	}

	loud := &ThreatWindow{TopTalker: &ThreatTopTalker{IP: "1.2.3.4", Requests: quietTopTalkerFloor}}
	if !ThreatWorthSending(loud) {
		t.Fatal("всплеск с одного адреса пропущен")
	}

	below := &ThreatWindow{TopTalker: &ThreatTopTalker{IP: "1.2.3.4", Requests: quietTopTalkerFloor - 1}}
	if ThreatWorthSending(below) {
		t.Fatal("обычный посетитель признан всплеском")
	}

	if ThreatWorthSending(nil) {
		t.Fatal("пустой указатель признан достойным отправки")
	}
}

// Разобранные строки придержанных окон не теряются.
//
// Курсор лога двигается внутри CollectTraffic независимо от того, ушёл ли
// отчёт. Без переноса счётчика панель «Безопасность кромки» печатала бы
// «разобрано N запросов за 24 ч» заниженным в разы — молча и без признаков.
func TestGateCarriesPendingParsed(t *testing.T) {
	g := NewReportGate()

	g.AddPendingParsed(120)
	g.AddPendingParsed(80)
	if got := g.TakePendingParsed(); got != 200 {
		t.Fatalf("накоплено %d, ожидалось 200", got)
	}
	if got := g.TakePendingParsed(); got != 0 {
		t.Fatalf("счётчик не обнулился: %d", got)
	}
	// Отрицательные и нулевые значения запас не портят.
	g.AddPendingParsed(0)
	g.AddPendingParsed(-5)
	if got := g.TakePendingParsed(); got != 0 {
		t.Fatalf("мусор попал в запас: %d", got)
	}
}

// Инвариант с платформой: тихое окно обязано приходить чаще, чем платформа
// собирает группу источника, иначе источник исчезает из выборки целиком и
// инцидент остаётся открытым навсегда.
//
// Окно оценки задано в apps/web/src/lib/threatAnalytics/runThreatAlerts.ts
// (`Date.now() - 10 * 60 * 1000`). Тест читает его оттуда, а не повторяет
// числом: расхождение двух констант иначе обнаружилось бы только в бою.
func TestQuietThreatFitsPlatformWindow(t *testing.T) {
	raw, err := os.ReadFile(
		"../../../web/src/lib/threatAnalytics/runThreatAlerts.ts")
	if err != nil {
		t.Skipf("файл платформы недоступен: %v", err)
	}

	m := regexp.MustCompile(`Date\.now\(\) - (\d+) \* 60 \* 1000`).FindSubmatch(raw)
	if m == nil {
		t.Skip("ориентир окна оценки в runThreatAlerts.ts изменился — тест пересобрать")
	}
	minutes, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("окно оценки не разобралось: %v", err)
	}

	window := time.Duration(minutes) * time.Minute
	if QuietThreatMaxAge >= window {
		t.Fatalf(
			"тихое окно %v не короче окна оценки платформы %v: источник будет "+
				"периодически выпадать из выборки, и инцидент останется открытым навсегда",
			QuietThreatMaxAge, window)
	}
}
