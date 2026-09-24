package agent

import (
	"context"
	"sync"
	"time"
)

// Ход применения релиза.
//
// ЗАЧЕМ. Первый подъём Supabase занимает до пятнадцати минут: девять образов,
// инициализация базы, ожидание готовности. Всё это время пользователь видел
// «Разворачивается» без единой подробности — и по опыту первых выкатов шёл
// смотреть журнал агента по SSH, то есть туда, куда платформа и должна была
// его не пускать.
//
// Агент и так держит вывод docker compose в руках — раньше он отправлял его
// хвост только после завершения, в составе итогового отчёта. Теперь тот же
// хвост уезжает раз в несколько секунд ПО ХОДУ работы, обычным отчётом со
// статусом applying. Новой ручки нет намеренно: канал отчёта подписан,
// проверен на принадлежность релиза хосту и существует с первого дня.
//
// Значения переменных затираются ДО отправки — тем же redactSecrets, что и в
// итоговом отчёте: хвост лога виден любому участнику проекта.

// ProgressFunc — куда сообщать о ходе применения. Второй аргумент — фаза
// («backup», «up», «stabilize»), третий — уже затёртый хвост вывода команды.
type ProgressFunc func(releaseID, phase, output string)

// Как часто отправлять ход выката. Реже — и прогресс перестаёт ощущаться
// живым; чаще — и подписанные запросы начинают заметно спорить с ограничением
// частоты на сервере.
const progressInterval = 5 * time.Second

// Сколько хвоста вывода держать и отправлять. Итоговый отчёт обрезает до 800
// символов; для живого прогресса нужно больше — docker compose печатает
// статус каждого слоя образа отдельной строкой. Серверный потолок на detail —
// 4000 символов, сюда закладываемся с запасом на JSON-обвязку и фазу.
const progressTailBytes = 2000

// tailBuffer — потокобезопасный буфер, хранящий только ХВОСТ записанного.
//
// Пишут в него stdout и stderr работающей команды, читает — тикер прогресса.
// Хранить вывод целиком нельзя: у долгого docker pull он растёт на мегабайты,
// а нужны из него ровно последние строки.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newTailBuffer(max int) *tailBuffer { return &tailBuffer{max: max} }

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		// Копия, а не срез: иначе подлежащий массив рос бы бесконечно,
		// удерживая весь когда-либо записанный вывод.
		trimmed := make([]byte, b.max)
		copy(trimmed, b.buf[len(b.buf)-b.max:])
		b.buf = trimmed
	}
	return len(p), nil
}

func (b *tailBuffer) Tail() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// dockerComposeStreamEnv — как dockerComposeEnv, но с периодической отдачей
// хвоста вывода через onTail, пока команда работает.
//
// onTail вызывается не чаще progressInterval и только когда хвост изменился:
// во время долгого ожидания готовности вывод стоит на месте, и слать одно и
// то же — занимать канал без пользы.
//
// Возвращается хвост вывода (не весь вывод): вызывающие и раньше обрезали его
// до сотен символов перед отправкой в отчёт.
func dockerComposeStreamEnv(
	ctx context.Context,
	dir, envFile string,
	onTail func(string),
	args ...string,
) (string, error) {
	full := []string{"compose"}
	if envFile != "" {
		full = append(full, "--env-file", envFile)
	}
	full = append(full, args...)

	cmd := newDockerCmd(ctx, dir, full...)

	tb := newTailBuffer(progressTailBytes)
	cmd.Stdout = tb
	cmd.Stderr = tb

	if err := cmd.Start(); err != nil {
		return "", err
	}

	// Отдельная горутина с явным ожиданием завершения: отчёты обязаны уйти ДО
	// того, как вызывающий отправит итоговый. Иначе запоздавший промежуточный
	// отчёт спорил бы с финальным за последнее слово — сервер от этого защищён,
	// но полагаться на его защиту вместо порядка отправки не стоит.
	done := make(chan struct{})
	var wg sync.WaitGroup
	if onTail != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(progressInterval)
			defer ticker.Stop()
			last := ""
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					t := tb.Tail()
					if t != last {
						last = t
						onTail(t)
					}
				}
			}
		}()
	}

	err := cmd.Wait()
	close(done)
	wg.Wait()
	return tb.Tail(), err
}
