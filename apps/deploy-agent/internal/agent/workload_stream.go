package agent

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Поток `docker events` — ТОЛЬКО триггер внеочередной выборки (ADR-0091,
// решение 5). Классифицирует по-прежнему сверка полного списка: поток может
// потерять событие (обрыв, переполнение у демона), сверка — нет. Поэтому из
// строки события не берётся ничего, кроме «пора посмотреть».
//
// Довод ADR-0061 против долгоживущего `docker events` («третий агент внутри
// второго») сюда не относится: агент развёртывания и так живёт постоянно, а
// `/events` прокси сокета пропускает без таймаутов (FlushInterval -1).

// workloadLifecycleActions — действия, после которых состояние контейнера
// могло смениться. exec_* сюда не входят: каждая проверка здоровья даёт три
// таких события (ADR-0061, факт 2), и выборка шла бы каждые несколько секунд.
var workloadLifecycleActions = map[string]bool{
	"create": true, "start": true, "restart": true, "die": true, "kill": true, "stop": true,
	"oom": true, "destroy": true, "pause": true, "unpause": true, "rename": true, "health_status": true,
}

// workloadStreamLineBytes — предел строки события. Метки compose и атрибуты
// образа делают строку длиннее 64 КиБ, на которых Scanner встаёт по умолчанию.
const workloadStreamLineBytes = 1 << 20

// workloadLifecycleEvent — строка потока будит выборку. Непонятная строка не
// будит: пропущенное всё равно поймает плановая выборка через минуту, а
// мусор в потоке не должен гонять docker inspect.
func workloadLifecycleEvent(line []byte) bool {
	var e struct {
		Type   string `json:"Type"`
		Action string `json:"Action"`
		// status — прежнее имя действия; новые демоны его не пишут.
		Status string `json:"status"`
	}
	if json.Unmarshal(line, &e) != nil || (e.Type != "" && e.Type != "container") {
		return false
	}
	// «health_status: unhealthy», «exec_start: pg_isready» — действие до двоеточия.
	action, _, _ := strings.Cut(cmp.Or(e.Action, e.Status), ":")
	return workloadLifecycleActions[strings.TrimSpace(action)]
}

// workloadWatchEvents держит один `docker events` до обрыва или отмены ctx.
// onStart — процесс запущен; onEvent — пришло действие жизненного цикла.
// Возвращает всегда ошибку: поток без конца, и его завершение — обрыв.
func workloadWatchEvents(ctx context.Context, onStart, onEvent func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := newDockerCmd(ctx, "", "events", "--filter", "type=container", "--format", "{{json .}}")
	stderr := newTailBuffer(512)
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("docker events не запущен: %w", err)
	}
	if onStart != nil {
		onStart()
	}

	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64<<10), workloadStreamLineBytes)
	for sc.Scan() {
		if workloadLifecycleEvent(sc.Bytes()) {
			onEvent()
		}
	}
	// Процесс гасится до Wait и тогда, когда поток кончился сам: сломанный
	// разбор оставил бы его писать в пайп, который больше никто не читает.
	// Wait обязателен — без него `docker events` остался бы зомби.
	cancel()
	waitErr := cmd.Wait()
	return fmt.Errorf("поток docker events оборвался: %v (разбор: %v): %s",
		waitErr, sc.Err(), tail(stderr.Tail(), 200))
}

// workloadFollowEvents держит поток, пока жив ctx. Обрыв — переподключение с
// отступом от min, удваивающимся до max; соединение, прожившее дольше max,
// сбрасывает отступ. После каждого переподключения — onResync: пока потока не
// было, события терялись, и полная сверка ловит всё, что случилось в разрыве.
func workloadFollowEvents(ctx context.Context, backoffMin, backoffMax time.Duration, onEvent, onResync func()) {
	backoff := backoffMin
	for reconnect := false; ; reconnect = true {
		var onStart func()
		if reconnect {
			onStart = onResync
		}
		started := time.Now()
		err := workloadWatchEvents(ctx, onStart, onEvent)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= backoffMax {
			backoff = backoffMin
		}
		fmt.Fprintf(os.Stderr, "нагрузки: %v; переподключение через %s\n", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, backoffMax)
	}
}
