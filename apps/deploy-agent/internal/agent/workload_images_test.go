package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Эталон образа релиза (ADR-0091, решение 6; критерий 4): другой образ под
// тем же тегом с пересозданием даёт mismatch, самовосстановление эталон не
// переснимает, смена идентичности релиза — переснимает.

func healthyApp(release, config string) AppliedRecord {
	return AppliedRecord{ReleaseID: release, ConfigHash: config, Status: "healthy",
		ComposeSha256: "compose-sha", EnvSha256: "env-sha", LastAttempt: testWorkloadStart}
}

func appliedWith(apps map[string]AppliedRecord) AppliedState { return AppliedState{Apps: apps} }

func evaluate(t *testing.T, w *WorkloadImages, applied AppliedState, cs ...WorkloadObservedContainer) map[string]WorkloadImageVerdict {
	t.Helper()
	verdicts, err := w.Evaluate(testWorkloadSample(minute(0), cs...), applied)
	if err != nil {
		t.Fatal(err)
	}
	return verdicts
}

func expectVerdict(t *testing.T, got WorkloadImageVerdict, verdict, reason, baseline, source string) {
	t.Helper()
	want := WorkloadImageVerdict{Verdict: verdict, Reason: reason, BaselineID: baseline, BaselineSource: source}
	if got != want {
		t.Fatalf("вердикт %+v, ожидался %+v", got, want)
	}
}

// deployedByAgent — агент сам применил релиз: эталон снимается с источником apply.
func deployedByAgent(t *testing.T, p Paths, applied AppliedState) *WorkloadImages {
	t.Helper()
	w := LoadWorkloadImages(p)
	w.BeginApply(appliedWith(nil))
	w.EndApply(applied)
	return w
}

// Критерий 4 ADR-0091: подменённый образ под тем же тегом, контейнер пересоздан.
func TestWorkloadImagesSubstitutedImageSameTag(t *testing.T) {
	applied := appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1")})
	w := deployedByAgent(t, Paths{StateDir: t.TempDir()}, applied)
	web := testRunning(1, "orbita", "web")
	expectVerdict(t, evaluate(t, w, applied, web)[web.ID], WorkloadVerdictMatch, "", web.ImageID, WorkloadBaselineApply)

	swapped := testRunning(2, "orbita", "web")
	swapped.ImageRef = web.ImageRef
	expectVerdict(t, evaluate(t, w, applied, swapped)[swapped.ID], WorkloadVerdictMismatch, "", web.ImageID, WorkloadBaselineApply)
}

// Самовосстановление поднимает упавшее тем, что есть на хосте, — в том числе
// подменённым образом. Пересними его эталон, подмена стала бы эталоном.
func TestWorkloadImagesSelfRecoveryKeepsBaseline(t *testing.T) {
	applied := appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1")})
	w := deployedByAgent(t, Paths{StateDir: t.TempDir()}, applied)
	web := testRunning(1, "orbita", "web")
	evaluate(t, w, applied, web)

	rec := applied.Apps["orbita"]
	rec.RecoveryAttempts, rec.LastRecovery, rec.LastAttempt = 3, testWorkloadStart.Add(time.Hour), testWorkloadStart.Add(time.Hour)
	recovered := appliedWith(map[string]AppliedRecord{"orbita": rec})
	swapped := testRunning(2, "orbita", "web")
	expectVerdict(t, evaluate(t, w, recovered, swapped)[swapped.ID], WorkloadVerdictMismatch, "", web.ImageID, WorkloadBaselineApply)
}

func TestWorkloadImagesIdentityChangeResnapshots(t *testing.T) {
	for name, change := range map[string]func(*AppliedRecord){
		"config_hash":    func(r *AppliedRecord) { r.ConfigHash = "h2" },
		"release_id":     func(r *AppliedRecord) { r.ReleaseID = "r2" },
		"compose_sha256": func(r *AppliedRecord) { r.ComposeSha256 = "other" },
		"env_sha256":     func(r *AppliedRecord) { r.EnvSha256 = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			applied := appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1")})
			w := deployedByAgent(t, Paths{StateDir: t.TempDir()}, applied)
			old := testRunning(1, "orbita", "web")
			evaluate(t, w, applied, old)

			rec := applied.Apps["orbita"]
			change(&rec)
			next := appliedWith(map[string]AppliedRecord{"orbita": rec})
			fresh := testRunning(2, "orbita", "web")
			w.BeginApply(applied)
			// Пока идёт применение — «не знаем», и эталон не снимается.
			expectVerdict(t, evaluate(t, w, next, fresh)[fresh.ID],
				WorkloadVerdictUnknown, WorkloadReasonApplyInProgress, old.ImageID, WorkloadBaselineApply)
			w.EndApply(next)
			expectVerdict(t, evaluate(t, w, next, fresh)[fresh.ID], WorkloadVerdictMatch, "", fresh.ImageID, WorkloadBaselineApply)
			// Эталон снимается один раз: прежний образ следующей выборкой — mismatch.
			expectVerdict(t, evaluate(t, w, next, old)[old.ID], WorkloadVerdictMismatch, "", fresh.ImageID, WorkloadBaselineApply)
		})
	}
}

// adopted — стек уже работал, когда агент его впервые увидел: эталон
// фиксирует, что стояло, и не доказывает, что образ был чистым.
func TestWorkloadImagesAdoptedThenApply(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	applied := appliedWith(map[string]AppliedRecord{"kassa": healthyApp("r1", "h1")})
	w := LoadWorkloadImages(p)
	api := testRunning(1, "kassa", "api")
	expectVerdict(t, evaluate(t, w, applied, api)[api.ID], WorkloadVerdictMatch, "", api.ImageID, WorkloadBaselineAdopted)

	// Эталон переживает перезапуск агента вместе с источником.
	w = LoadWorkloadImages(p)
	expectVerdict(t, evaluate(t, w, applied, api)[api.ID], WorkloadVerdictMatch, "", api.ImageID, WorkloadBaselineAdopted)

	// Смена идентичности при живом агенте — apply, даже если начало
	// применения агент не видел: прежняя идентичность была записана.
	rec := applied.Apps["kassa"]
	rec.ConfigHash = "h2"
	applied = appliedWith(map[string]AppliedRecord{"kassa": rec})
	next := testRunning(2, "kassa", "api")
	expectVerdict(t, evaluate(t, w, applied, next)[next.ID], WorkloadVerdictMatch, "", next.ImageID, WorkloadBaselineApply)
}

// Применение другого приложения в первую минуту агента не делает эталон
// уже работавшего стека «снятым после применения».
func TestWorkloadImagesApplyOfAnotherAppKeepsAdopted(t *testing.T) {
	kassa := healthyApp("r1", "h1")
	before := appliedWith(map[string]AppliedRecord{"kassa": kassa})
	after := appliedWith(map[string]AppliedRecord{"kassa": kassa, "orbita": healthyApp("r9", "h9")})
	w := LoadWorkloadImages(Paths{StateDir: t.TempDir()})
	w.BeginApply(before)
	w.EndApply(after)

	api, web := testRunning(1, "kassa", "api"), testRunning(2, "orbita", "web")
	verdicts := evaluate(t, w, after, api, web)
	expectVerdict(t, verdicts[api.ID], WorkloadVerdictMatch, "", api.ImageID, WorkloadBaselineAdopted)
	expectVerdict(t, verdicts[web.ID], WorkloadVerdictMatch, "", web.ImageID, WorkloadBaselineApply)
}

func TestWorkloadImagesUnknownReasons(t *testing.T) {
	failed := healthyApp("r1", "h1")
	failed.Status = "failed"
	applied := appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1"), "kassa": failed})
	w := deployedByAgent(t, Paths{StateDir: t.TempDir()}, applied)

	// Стек платформы без работающих контейнеров — снимать нечего, эталона нет.
	stopped := testRunning(1, "orbita", "web")
	stopped.State, stopped.Running = "exited", false
	legacy := testRunning(2, "", "legacy-cron")
	foreign := testRunning(3, "shop", "db")
	kassa := testRunning(4, "kassa", "api")
	verdicts := evaluate(t, w, applied, stopped, legacy, foreign, kassa)
	expectVerdict(t, verdicts[stopped.ID], WorkloadVerdictUnknown, WorkloadReasonNoBaseline, "", "")
	expectVerdict(t, verdicts[legacy.ID], WorkloadVerdictUnknown, WorkloadReasonNotPlatformStack, "", "")
	expectVerdict(t, verdicts[foreign.ID], WorkloadVerdictUnknown, WorkloadReasonNotPlatformStack, "", "")
	expectVerdict(t, verdicts[kassa.ID], WorkloadVerdictUnknown, WorkloadReasonReleaseNotHealthy, "", "")

	// Первая выборка с работающим контейнером снимает эталон.
	web := testRunning(1, "orbita", "web")
	expectVerdict(t, evaluate(t, w, applied, web)[web.ID], WorkloadVerdictMatch, "", web.ImageID, WorkloadBaselineApply)

	noImage := testRunning(5, "orbita", "web")
	noImage.ImageID = ""
	expectVerdict(t, evaluate(t, w, applied, noImage)[noImage.ID], WorkloadVerdictUnknown, WorkloadReasonImageUnknown, web.ImageID, WorkloadBaselineApply)
}

func TestWorkloadImagesForgetsRemovedApps(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	applied := appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1")})
	w := LoadWorkloadImages(p)
	evaluate(t, w, applied, testRunning(1, "orbita", "web"))
	evaluate(t, w, appliedWith(nil))
	if _, ok := LoadWorkloadImages(p).state.Apps["orbita"]; ok {
		t.Fatal("эталон снятого приложения остался")
	}
}

func TestWorkloadImagesSaveFailureReported(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	w := LoadWorkloadImages(Paths{StateDir: dir})
	applied := appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1")})
	web := testRunning(1, "orbita", "web")
	verdicts, err := w.Evaluate(testWorkloadSample(minute(0), web), applied)
	if err == nil {
		t.Fatal("ошибка записи эталона не отдана")
	}
	// Вердикт верен и без диска: эталон снят первой выборкой и в памяти остаётся.
	expectVerdict(t, verdicts[web.ID], WorkloadVerdictMatch, "", web.ImageID, WorkloadBaselineAdopted)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	swapped := testRunning(2, "orbita", "web")
	verdicts, err = w.Evaluate(testWorkloadSample(minute(1), swapped), applied)
	if err != nil || verdicts[swapped.ID].Verdict != WorkloadVerdictMismatch {
		t.Fatalf("после сбоя записи эталон переснят: %+v %v", verdicts[swapped.ID], err)
	}
	if _, ok := LoadWorkloadImages(Paths{StateDir: dir}).state.Apps["orbita"]; !ok {
		t.Fatal("эталон не дописан на диск следующей выборкой")
	}
}
