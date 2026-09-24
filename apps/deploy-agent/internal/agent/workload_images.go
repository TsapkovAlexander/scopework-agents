package agent

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// Эталон образа релиза и вердикт (ADR-0091, решение 6).
//
// Ни applied.json, ни желаемое состояние образов не несут, поэтому до
// подписанного манифеста с дайджестами эталон снимается с работающих
// контейнеров: id образа по сервисам compose-проекта приложения (проект =
// slug), первой выборкой после смены идентичности релиза. Разрешать тег в
// момент сверки нельзя: тег указывает на то, что есть сейчас, и «другой образ
// под тем же тегом с пересозданием» прошёл бы как match (альтернатива «к»).

// Вердикт, причины и источник эталона — значения полей image секции.
const (
	WorkloadVerdictMatch    = "match"
	WorkloadVerdictMismatch = "mismatch"
	WorkloadVerdictUnknown  = "unknown"

	WorkloadReasonApplyInProgress   = "apply_in_progress"
	WorkloadReasonNoBaseline        = "no_baseline"
	WorkloadReasonNotPlatformStack  = "not_platform_stack"
	WorkloadReasonReleaseNotHealthy = "release_not_healthy"
	WorkloadReasonImageUnknown      = "image_unknown"

	// apply — эталон снят после применения, которое агент видел; adopted —
	// у стека, который уже работал, когда агент его впервые увидел: он
	// фиксирует, что стояло, и не доказывает, что образ был чистым.
	WorkloadBaselineApply   = "apply"
	WorkloadBaselineAdopted = "adopted"
)

const workloadImagesFileVersion = 1

// WorkloadImageVerdict — вердикт по одному контейнеру; BaselineID и
// BaselineSource пусты, пока эталона нет.
type WorkloadImageVerdict struct {
	Verdict, Reason            string
	BaselineID, BaselineSource string
}

// workloadReleaseIdentity — идентичность релиза приложения.
//
// Поля самовосстановления (LastAttempt, LastRecovery, RecoveryAttempts) в неё
// не входят: иначе эталон переснимался бы после каждого самовосстановления, и
// подменённый образ, поднятый им, стал бы эталоном.
type workloadReleaseIdentity struct {
	ReleaseID     string `json:"release_id"`
	ConfigHash    string `json:"config_hash"`
	ComposeSha256 string `json:"compose_sha256"`
	EnvSha256     string `json:"env_sha256"`
}

func workloadIdentityOf(r AppliedRecord) workloadReleaseIdentity {
	return workloadReleaseIdentity{ReleaseID: r.ReleaseID, ConfigHash: r.ConfigHash,
		ComposeSha256: r.ComposeSha256, EnvSha256: r.EnvSha256}
}

type workloadImageRecord struct {
	Identity    workloadReleaseIdentity `json:"identity"`
	Source      string                  `json:"source"`
	Snapshotted bool                    `json:"snapshotted"`
	Services    map[string]string       `json:"services,omitempty"`
}

type workloadImagesFile struct {
	V    int                            `json:"v"`
	Apps map[string]workloadImageRecord `json:"apps"`
}

// WorkloadImages — эталоны стеков платформы. Безопасна для двух горутин:
// применение идёт в основном цикле, выборка — в своей.
type WorkloadImages struct {
	mu       sync.Mutex
	path     string
	state    workloadImagesFile
	dirty    bool // в памяти новее, чем на диске
	applying bool
	before   map[string]workloadReleaseIdentity
	// appliedHere — приложения, чью идентичность сменило применение, которое
	// этот процесс видел от начала до конца: их эталон — apply.
	appliedHere map[string]bool
}

func workloadImagesPath(p Paths) string { return filepath.Join(p.StateDir, "workload-images.json") }

// LoadWorkloadImages читает эталоны. Битый файл равносилен пустому: стеки
// получат эталон adopted заново — слабее, но честно помечено.
func LoadWorkloadImages(p Paths) *WorkloadImages {
	w := &WorkloadImages{path: workloadImagesPath(p), appliedHere: map[string]bool{},
		state: workloadImagesFile{V: workloadImagesFileVersion, Apps: map[string]workloadImageRecord{}}}
	raw, err := os.ReadFile(w.path)
	if err != nil || len(raw) > workloadEventsMaxFileBytes {
		return w
	}
	var file workloadImagesFile
	if json.Unmarshal(raw, &file) == nil && file.V == workloadImagesFileVersion && file.Apps != nil {
		w.state = file
	}
	return w
}

// BeginApply — применение началось; before — applied.json до него. Пока оно
// идёт, вердикт стеков платформы — unknown (apply_in_progress), и эталон не
// снимается: стек в середине пересоздания — не релиз.
func (w *WorkloadImages) BeginApply(before AppliedState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.applying = true
	w.before = make(map[string]workloadReleaseIdentity, len(before.Apps))
	for slug, rec := range before.Apps {
		w.before[slug] = workloadIdentityOf(rec)
	}
}

// EndApply — применение закончилось; after — applied.json после него.
// Приложения, чья идентичность за это время сменилась, применил сам агент.
func (w *WorkloadImages) EndApply(after AppliedState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.applying {
		return
	}
	for slug, rec := range after.Apps {
		if prev, ok := w.before[slug]; !ok || prev != workloadIdentityOf(rec) {
			w.appliedHere[slug] = true
		}
	}
	w.applying, w.before = false, nil
}

// Evaluate сверяет образы выборки с эталонами и снимает эталон там, где
// идентичность релиза сменилась. Зовётся на каждую выборку; applied —
// LoadApplied на момент выборки. Вердикты — по id контейнера.
//
// Ошибка — эталон не записан на диск. Вердикты верны и без диска: снятый
// эталон остаётся в памяти, и запись повторится следующей выборкой.
func (w *WorkloadImages) Evaluate(s WorkloadSample, applied AppliedState) (map[string]WorkloadImageVerdict, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.applying {
		w.track(s, applied)
	}
	verdicts := make(map[string]WorkloadImageVerdict, len(s.Containers))
	for _, c := range s.Containers {
		verdicts[c.ID] = w.verdict(c, applied)
	}
	if !w.dirty {
		return verdicts, nil
	}
	return verdicts, w.save()
}

// track замечает смену идентичности и снимает эталон первой выборкой после неё.
func (w *WorkloadImages) track(s WorkloadSample, applied AppliedState) {
	for _, slug := range slices.Sorted(maps.Keys(applied.Apps)) {
		rec := applied.Apps[slug]
		// Идентичность определена только у здорового релиза: неудачное
		// применение — не релиз, и эталон с него снимать нельзя.
		if rec.Status != "healthy" {
			continue
		}
		identity := workloadIdentityOf(rec)
		cur, known := w.state.Apps[slug]
		if !known || cur.Identity != identity {
			source := WorkloadBaselineAdopted
			// Прежняя идентичность записана — значит, её сменил агент: чужой
			// applied.json не пишет.
			if known || w.appliedHere[slug] {
				source = WorkloadBaselineApply
			}
			cur = workloadImageRecord{Identity: identity, Source: source}
			w.dirty = true
		}
		delete(w.appliedHere, slug)
		if !cur.Snapshotted {
			if services := workloadSnapshot(s, slug); len(services) > 0 {
				cur.Services, cur.Snapshotted = services, true
				w.dirty = true
			}
		}
		w.state.Apps[slug] = cur
	}
	for slug := range w.state.Apps {
		if _, ok := applied.Apps[slug]; !ok {
			delete(w.state.Apps, slug)
			w.dirty = true
		}
	}
}

// workloadSnapshot — id образа по сервисам работающих контейнеров проекта.
// Разовые `compose run` в эталон не идут. У нескольких реплик сервиса эталон
// — реплика с наименьшим именем: расхождение реплик само станет mismatch.
func workloadSnapshot(s WorkloadSample, slug string) map[string]string {
	running := slices.DeleteFunc(slices.Clone(s.Containers), func(c WorkloadObservedContainer) bool {
		return c.ComposeProject != slug || c.ComposeService == "" || c.ComposeOneoff ||
			!(c.Running || c.Restarting) || !workloadImageIDPattern.MatchString(c.ImageID)
	})
	slices.SortFunc(running, func(a, b WorkloadObservedContainer) int { return cmp.Compare(a.Name, b.Name) })
	services := map[string]string{}
	for _, c := range running {
		if _, taken := services[c.ComposeService]; !taken {
			services[c.ComposeService] = c.ImageID
		}
	}
	return services
}

func (w *WorkloadImages) verdict(c WorkloadObservedContainer, applied AppliedState) WorkloadImageVerdict {
	rec, platform := applied.Apps[c.ComposeProject]
	if c.ComposeProject == "" || !platform {
		return WorkloadImageVerdict{Verdict: WorkloadVerdictUnknown, Reason: WorkloadReasonNotPlatformStack}
	}
	v := WorkloadImageVerdict{Verdict: WorkloadVerdictUnknown}
	stored, known := w.state.Apps[c.ComposeProject]
	if baseline := stored.Services[c.ComposeService]; known && baseline != "" {
		v.BaselineID, v.BaselineSource = baseline, stored.Source
	}
	switch {
	case w.applying:
		v.Reason = WorkloadReasonApplyInProgress
	case rec.Status != "healthy":
		v.Reason = WorkloadReasonReleaseNotHealthy
	case v.BaselineID == "" || stored.Identity != workloadIdentityOf(rec):
		v.Reason = WorkloadReasonNoBaseline
	case !workloadImageIDPattern.MatchString(c.ImageID):
		v.Reason = WorkloadReasonImageUnknown
	case c.ImageID == v.BaselineID:
		v.Verdict = WorkloadVerdictMatch
	default:
		v.Verdict = WorkloadVerdictMismatch
	}
	return v
}

func (w *WorkloadImages) save() error {
	raw, err := json.Marshal(w.state)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(w.path, raw, 0o600); err != nil {
		return fmt.Errorf("эталон образов не сохранён: %w", err)
	}
	w.dirty = false
	return nil
}
