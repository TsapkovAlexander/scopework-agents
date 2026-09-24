package composeguard

import (
	"fmt"
	"strconv"
)

// Послабления политики (С1.5, ADR-0092, решение 11).
//
// Словарь закрытый и живёт здесь, а не в данных: новый вид послабления —
// новая версия агента и подписанта. Грант, подписанный корнем, может лишь
// выбрать из того, что эта версия умеет ограничить; всё прочее в нём —
// ошибка, а не «неизвестно, значит можно».
//
// Сейчас вид один. `ports` запрещён целиком, а шаблонам с протоколами не
// поверх HTTP (почта, TURN) нужен прямой порт хоста. `cap_add`, `sysctls` и
// подобные сюда не годятся: прокси сокета агента отбивает их независимо от
// гранта, и послабление работало бы только в режиме root.

// AllowPublishPort — публикация одного порта хоста одним сервисом.
const AllowPublishPort = "publish_port"

// Allowance — одно послабление. Форма JSON — та, что едет в гранте корня:
// `{kind, service, port, protocol}`.
type Allowance struct {
	Kind     string `json:"kind"`
	Service  string `json:"service"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// ValidateAllowances отвергает всё, что словарь не описывает.
func ValidateAllowances(list []Allowance) error {
	for i, a := range list {
		if a.Kind != AllowPublishPort {
			return fmt.Errorf("послабление %d: вид %q политике неизвестен", i, tail(a.Kind, 40))
		}
		if a.Service == "" {
			return fmt.Errorf("послабление %d: не назван сервис", i)
		}
		if a.Port < 1 || a.Port > 65535 {
			return fmt.Errorf("послабление %d: порт %d вне 1–65535", i, a.Port)
		}
		if a.Protocol != "tcp" && a.Protocol != "udp" {
			return fmt.Errorf("послабление %d: протокол %q — допустимы tcp и udp", i, tail(a.Protocol, 20))
		}
	}
	return nil
}

// portsCovered — покрыта ли КАЖДАЯ запись ports сервиса послаблением этого же
// сервиса. Одна непокрытая запись оставляет запрет целиком: иначе грант на
// один порт открывал бы соседний «в придачу».
//
// Запись берётся в нормализованном виде (`published` — строка, протокол
// проставлен). Диапазон, эфемерный порт и любая форма, которую compose так не
// отдаёт, не покрываются: грант называет ровно один порт хоста. Адрес привязки
// и порт контейнера грант не ограничивает — он говорит о порте хоста.
func portsCovered(service string, ports []any, allow []Allowance) bool {
	if len(allow) == 0 {
		return false
	}
	for _, entry := range ports {
		obj, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		published, _ := obj["published"].(string)
		protocol, _ := obj["protocol"].(string)
		if protocol == "" {
			protocol = "tcp"
		}
		covered := false
		for _, a := range allow {
			if a.Kind == AllowPublishPort && a.Service == service &&
				published == strconv.Itoa(a.Port) && protocol == a.Protocol {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
