package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

// RefuseTask отказывает в задании по политике хоста (ADR-0095, п. 2) и
// отчитывается об этом платформе.
//
// Отчёт идёт ТЕМ ЖЕ путём, что у настоящего исхода этого вида: задание любого
// вида закрывает одна RPC платформы, и отказ, пришедший другой дорогой,
// остался бы вторым местом, где задание может повиснуть. Молчаливый отказ
// хуже громкого: задание висело бы в pending, агент брал бы его каждый такт, а
// человек смотрел бы на «выполняется…» без конца.
//
// Отметка task.json — после принятого отчёта, как у RunTask: недоставленный
// отказ повторится следующим тактом, доставленный — больше не шлётся.
func RefuseTask(ctx context.Context, client *Client, id Identity, p Paths, task HostTask, reason string) error {
	markPath := filepath.Join(p.StateDir, "task.json")
	var mark taskMark
	if raw, err := os.ReadFile(markPath); err == nil {
		_ = json.Unmarshal(raw, &mark)
	}
	if mark.TaskID == task.ID || task.ID == "" {
		return nil
	}

	failure := "не исполнено: политика сервера — " + reason
	var err error
	switch task.Kind {
	case "backup":
		err = client.ReportBackup(ctx, id, task.ID, "", 0, failure, BackupUpload{})
	case "restore":
		err = client.ReportRestore(ctx, id, task.ID, task.BackupSet, 0, failure)
	default:
		// export, migrate-data, start-stack, stop-stack и незнакомый вид:
		// платформа закрывает их ручкой переноса данных.
		err = client.ReportMigration(ctx, id, task.ID, MigrateResult{}, failure)
	}
	if err != nil {
		return err
	}

	// Неотправленный исход восстановления переносится как есть — отказ в
	// другом задании не должен его стереть.
	mark.TaskID = task.ID
	return saveTaskMark(markPath, mark)
}
