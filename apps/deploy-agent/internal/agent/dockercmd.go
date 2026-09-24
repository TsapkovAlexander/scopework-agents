package agent

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// Запуск docker так, чтобы срок ГАРАНТИРОВАННО освобождал цикл агента.
//
// ЗАЧЕМ. `exec.CommandContext` по истечении срока убивает ровно один процесс —
// тот, который запустили. А `docker compose` это плагин: CLI поднимает
// отдельный процесс `cli-plugins/docker-compose`, и он наследует наши пайпы.
// `cmd.Wait()` ждёт закрытия ВСЕХ держателей write-конца, поэтому осиротевший
// плагин продолжает держать пайп, а Wait висит — ровно в том состоянии, от
// которого срок и защищал: цикл агента не завершается, желаемое состояние не
// забирается, «остановить» и «удалить» из интерфейса не доезжают никогда.
//
// ЧТО ДЕЛАЕМ. Своя группа процессов и сигнал по всей группе при отмене — тогда
// плагин умирает вместе с CLI. Плюс WaitDelay: даже если кто-то из потомков
// переживёт сигнал, Wait не будет ждать его дольше отведённого срока, а
// принудительно закроет пайпы и вернёт ошибку.
//
// ЧЕГО ЭТО НЕ ЧИНИТ. Сама сборка живёт в демоне docker и продолжится: убить её
// снаружи нельзя. Следующий такт застанет её идущей, и `docker compose build`
// подхватит уже сделанные слои — это нормально и лучше, чем висящий агент.

// waitDelayAfterKill — сколько ждать закрытия пайпов после сигнала группе.
const waitDelayAfterKill = 30 * time.Second

// newDockerCmd собирает команду docker с гарантированным освобождением цикла.
func newDockerCmd(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	cmd.Env = dockerEnv()

	// Своя группа процессов: без неё сигнал уходит только CLI, а плагин
	// compose остаётся жив и держит наши пайпы.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Отрицательный pid — вся группа. Ошибку не поднимаем: процесс мог уже
		// завершиться сам, и это не повод считать отмену неудавшейся.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil
	}
	cmd.WaitDelay = waitDelayAfterKill

	return cmd
}
