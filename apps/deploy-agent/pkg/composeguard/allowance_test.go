package composeguard

import (
	"strings"
	"testing"
)

// Модели ниже — в том виде, в каком их отдаёт `docker compose config --format
// json`: запись ports — объект, published — строка, протокол проставлен.
const mailTCP25 = `{"services":{"mail":{"image":"x","ports":[
	{"mode":"ingress","target":25,"published":"25","protocol":"tcp"}
]}}}`

func checkAllowing(t *testing.T, json string, allow ...Allowance) []Violation {
	t.Helper()
	v, err := Check([]byte(json), Options{Roots: roots(), Allowances: allow})
	if err != nil {
		t.Fatalf("разбор не удался: %v", err)
	}
	return v
}

func hasPortsViolation(v []Violation) bool {
	for _, one := range v {
		if strings.HasPrefix(one.Reason, "ports:") {
			return true
		}
	}
	return false
}

func publish(service string, port int, protocol string) Allowance {
	return Allowance{Kind: AllowPublishPort, Service: service, Port: port, Protocol: protocol}
}

// Без гранта ports по-прежнему запрещён целиком: словарь послаблений не меняет
// поведение для всех, у кого подписанного разрешения нет.
func TestPortsRefusedWithoutAllowance(t *testing.T) {
	if v := checkAllowing(t, mailTCP25); !hasPortsViolation(v) {
		t.Fatalf("ports без послабления принят: %v", v)
	}
}

// Послабление снимает ровно то, что названо: этот сервис, этот порт хоста,
// этот протокол. Протокол — часть разрешения: udp-порт TURN не открывает tcp.
func TestPublishPortAllowsExactServicePortProtocol(t *testing.T) {
	if v := checkAllowing(t, mailTCP25, publish("mail", 25, "tcp")); len(v) != 0 {
		t.Fatalf("точное послабление не сработало: %v", v)
	}

	udp := `{"services":{"turn":{"image":"x","ports":[
		{"mode":"ingress","target":3478,"published":"3478","protocol":"udp"}
	]}}}`
	if v := checkAllowing(t, udp, publish("turn", 3478, "udp")); len(v) != 0 {
		t.Fatalf("udp-послабление не сработало: %v", v)
	}
	if v := checkAllowing(t, udp, publish("turn", 3478, "tcp")); !hasPortsViolation(v) {
		t.Fatalf("tcp-послабление открыло udp-порт: %v", v)
	}

	// Адрес привязки и порт контейнера послабление не ограничивает: грант
	// говорит о порте хоста, а не о том, куда он ведёт внутри.
	bound := `{"services":{"mail":{"image":"x","ports":[
		{"mode":"ingress","host_ip":"127.0.0.1","target":2525,"published":"25","protocol":"tcp"}
	]}}}`
	if v := checkAllowing(t, bound, publish("mail", 25, "tcp")); len(v) != 0 {
		t.Fatalf("послабление не сработало при host_ip и другом target: %v", v)
	}
}

// Грант на один порт не открывает соседний. Одна непокрытая запись оставляет
// нарушение для всего сервиса: иначе второй порт проехал бы «в придачу».
func TestPublishPortOtherPortRefused(t *testing.T) {
	if v := checkAllowing(t, mailTCP25, publish("mail", 587, "tcp")); !hasPortsViolation(v) {
		t.Fatalf("грант на 587 открыл 25: %v", v)
	}

	two := `{"services":{"mail":{"image":"x","ports":[
		{"mode":"ingress","target":25,"published":"25","protocol":"tcp"},
		{"mode":"ingress","target":22,"published":"22","protocol":"tcp"}
	]}}}`
	if v := checkAllowing(t, two, publish("mail", 25, "tcp")); !hasPortsViolation(v) {
		t.Fatalf("непокрытый порт 22 проехал вместе с разрешённым 25: %v", v)
	}
	if v := checkAllowing(t, two, publish("mail", 25, "tcp"), publish("mail", 22, "tcp")); len(v) != 0 {
		t.Fatalf("оба порта покрыты, а нарушение осталось: %v", v)
	}
}

// Грант привязан к сервису: разрешение для почты не открывает порт веб-сервису
// того же стека.
func TestPublishPortOtherServiceRefused(t *testing.T) {
	web := `{"services":{"web":{"image":"x","ports":[
		{"mode":"ingress","target":25,"published":"25","protocol":"tcp"}
	]},"mail":{"image":"x"}}}`
	v := checkAllowing(t, web, publish("mail", 25, "tcp"))
	if !hasPortsViolation(v) {
		t.Fatalf("грант сервиса mail открыл порт сервису web: %v", v)
	}
	for _, one := range v {
		if one.Service != "web" {
			t.Fatalf("нарушение не у того сервиса: %v", one)
		}
	}
}

// Диапазон и эфемерный порт (published не задан) послаблением не покрываются:
// грант называет один порт, а диапазон — это много портов, эфемерный — любой.
func TestPublishPortRangeRefused(t *testing.T) {
	for name, body := range map[string]string{
		"диапазон": `{"services":{"mail":{"image":"x","ports":[
			{"mode":"ingress","target":25,"published":"25-30","protocol":"tcp"}
		]}}}`,
		"эфемерный": `{"services":{"mail":{"image":"x","ports":[
			{"mode":"ingress","target":25,"protocol":"tcp"}
		]}}}`,
		"ведущий ноль": `{"services":{"mail":{"image":"x","ports":[
			{"mode":"ingress","target":25,"published":"025","protocol":"tcp"}
		]}}}`,
		"короткая форма": `{"services":{"mail":{"image":"x","ports":["25:25"]}}}`,
	} {
		if v := checkAllowing(t, body, publish("mail", 25, "tcp")); !hasPortsViolation(v) {
			t.Errorf("%s: принят по гранту на один порт: %v", name, v)
		}
	}
}

// Словарь закрытый: незнакомый вид, порт вне диапазона, чужой протокол и
// пустой сервис — ошибка, и Check с такими послаблениями не выносит решения
// вовсе. Молча пропустить незнакомое значило бы, что новый вид гранта, выпущенный
// для новой версии агента, на старой снимал бы неизвестно что.
func TestUnknownAllowanceKindRejected(t *testing.T) {
	for name, a := range map[string]Allowance{
		"незнакомый вид":   {Kind: "cap_add", Service: "mail", Port: 25, Protocol: "tcp"},
		"пустой вид":       {Service: "mail", Port: 25, Protocol: "tcp"},
		"порт ноль":        publish("mail", 0, "tcp"),
		"порт за пределом": publish("mail", 65536, "tcp"),
		"чужой протокол":   publish("mail", 25, "sctp"),
		"пустой протокол":  publish("mail", 25, ""),
		"пустой сервис":    publish("", 25, "tcp"),
	} {
		if err := ValidateAllowances([]Allowance{a}); err == nil {
			t.Errorf("%s: ValidateAllowances принял %+v", name, a)
		}
		if _, err := Check([]byte(mailTCP25), Options{Roots: roots(), Allowances: []Allowance{a}}); err == nil {
			t.Errorf("%s: Check вынес решение с негодным послаблением %+v", name, a)
		}
	}
	if err := ValidateAllowances([]Allowance{publish("mail", 25, "tcp"), publish("turn", 3478, "udp")}); err != nil {
		t.Fatalf("годные послабления отвергнуты: %v", err)
	}
	if err := ValidateAllowances(nil); err != nil {
		t.Fatalf("пустой список отвергнут: %v", err)
	}
}
