package agent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Сверка дрейфа v0 (ADR-0078).
//
// Агент сравнивает compose, .env каждого приложения и Caddyfile хоста с тем,
// что записал сам, — до того, как такт их перезапишет. Базовая линия — sha256
// записанных байтов (applied.json, proxy-written.sha256), а не отрисовка
// желаемого: желаемое меняется раньше диска, и сверка с ним путала бы наше
// изменение в пути с чужой правкой.
//
// Атрибуция без подписи: «не наше» здесь значит только «не совпало с тем, что
// агент помнит о своей записи». У клиента root, и память агента — свидетельство,
// а не доказательство (ADR-0066, 7.6).

const (
	driftStateFileName   = "drift-state.json"
	proxyWrittenFileName = "proxy-written.sha256"

	driftObjectCompose   = "compose"
	driftObjectEnv       = "env"
	driftObjectCaddyfile = "caddyfile"

	driftMatch      = "match"
	driftMismatch   = "mismatch"
	driftMissing    = "missing"
	driftUnreadable = "unreadable"
	driftNoBaseline = "no_baseline"

	driftInTransit          = "in_transit"
	driftForeign            = "foreign"
	driftForeignOverPending = "foreign_over_pending"
)

// driftStateMaxFileBytes — больше этого файл последнего известного не читаем:
// штатно в нём две строки на приложение.
const driftStateMaxFileBytes = 1 << 20

func (p Paths) driftStatePath() string   { return filepath.Join(p.StateDir, driftStateFileName) }
func (p Paths) proxyWrittenPath() string { return filepath.Join(p.StateDir, proxyWrittenFileName) }

// noteProxyWritten ставит отметку записанного Caddyfile.
//
// Отметка не удалась — старую убираем: отметка от прошлой записи при новом
// файле дала бы ложный дрейф на каждом такте, а без отметки сверка честно
// скажет «нет данных».
func noteProxyWritten(p Paths, sha string) {
	err := os.MkdirAll(p.StateDir, 0o700)
	if err == nil {
		err = writeFileAtomic(p.proxyWrittenPath(), []byte(sha), 0o600)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "отметка записанного Caddyfile не сохранена: %v\n", err)
		_ = os.Remove(p.proxyWrittenPath())
	}
}

// restoredBaseline переносит в базовую линию файлы, которые восстановление
// вернуло из набора копий.
//
// Совпадение диска с набором сверяется побайтно: восстановление могло
// оборваться до записи файла, и тогда на диске прежний, а базовая линия
// остаётся прежней же.
func restoredBaseline(p Paths, slug, setDir string, rec AppliedRecord) AppliedRecord {
	for name, sha := range map[string]*string{
		"docker-compose.yml": &rec.ComposeSha256,
		".env":               &rec.EnvSha256,
	} {
		fromSet, err := os.ReadFile(filepath.Join(setDir, name))
		if err != nil {
			continue
		}
		onDisk, err := os.ReadFile(filepath.Join(p.appDir(slug), name))
		if err != nil || !bytes.Equal(fromSet, onDisk) {
			continue
		}
		sum := sha256.Sum256(onDisk)
		*sha = hex.EncodeToString(sum[:])
	}
	return rec
}

// adoptRestoredBaseline — то же для восстановления по кнопке владельца, где
// отметки живут только на диске.
func adoptRestoredBaseline(p Paths, slug, setDir string) {
	state := LoadApplied(p)
	rec, ok := state.Apps[slug]
	if !ok {
		return
	}
	next := restoredBaseline(p, slug, setDir, rec)
	if next == rec {
		return
	}
	state.Apps[slug] = next
	if err := SaveApplied(p, state); err != nil {
		fmt.Fprintf(os.Stderr, "базовая линия после восстановления %s не сохранена: %v\n", slug, err)
	}
}

// driftObservation — итог сверки одного объекта.
type driftObservation struct {
	key    string
	record DriftRecord
	// adopt — базовая линия выведена из желаемого (переход со старого
	// applied.json) и совпала с диском; закрепляется при фиксации.
	adopt string
}

// ObserveDrift сверяет файлы с базовой линией и возвращает сигналы для очереди.
//
// Сигнал — только на переходе статуса и при первом наблюдении объекта.
// Последнее известное сдвигает commit, и звать его можно ТОЛЬКО после того,
// как сигналы легли в очередь: иначе сбой записи очереди потерял бы событие
// навсегда — следующий такт увидел бы тот же статус и промолчал.
//
// Ошибка — только когда файл последнего известного не прочитать вовсе; тексты
// ошибок содержимого файлов не несут.
func ObserveDrift(p Paths, apps []DesiredApp, opts ProxyOptions, now time.Time) ([]DriftRecord, func() error, error) {
	previous, err := loadDriftState(p)
	if err != nil {
		return nil, nil, err
	}

	desired := make(map[string]DesiredApp, len(apps))
	for _, app := range apps {
		desired[app.Slug] = app
	}

	var observed []driftObservation
	if obs, ok := observeCaddyfile(p, apps, opts); ok {
		observed = append(observed, obs)
	}

	applied := LoadApplied(p)
	slugs := make([]string, 0, len(applied.Apps))
	for slug := range applied.Apps {
		// Мусор в отметках в путь на диске не превращаем — и сигнал к нему не
		// привязать: платформа отбросила бы запись.
		if safeSlug.MatchString(slug) {
			slugs = append(slugs, slug)
		}
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		app, found := desired[slug]
		observed = append(observed, observeAppFiles(p, slug, applied.Apps[slug], app, found)...)
	}

	next := make(map[string]string, len(observed))
	var records []DriftRecord
	for _, obs := range observed {
		prev, known := previous[obs.key]
		// Объект, которого нет среди наблюдаемых (приложение снято), в next не
		// попадает — забывается без события.
		if known && prev == obs.record.Status {
			next[obs.key] = prev
			continue
		}
		// Больше записей за такт очередь не примет; остальные останутся
		// непереданными в последнем известном и уйдут следующим тактом.
		if len(records) > MaxDriftIdx {
			if known {
				next[obs.key] = prev
			}
			continue
		}
		obs.record.ObservedAt = now
		records = append(records, obs.record)
		next[obs.key] = obs.record.Status
	}

	commit := func() error {
		if err := adoptBaselines(p, observed); err != nil {
			return err
		}
		return saveDriftState(p, next)
	}
	return records, commit, nil
}

// observeAppFiles сверяет compose и .env одного приложения.
func observeAppFiles(p Paths, slug string, rec AppliedRecord, app DesiredApp, found bool) []driftObservation {
	// Желаемое совпадает с применённым — значит расхождение с диском не может
	// быть нашим изменением в пути.
	settled := found && app.ShouldRun() &&
		rec.ReleaseID == app.ReleaseID && rec.ConfigHash == configHash(app)
	// Отрисовать применённое из желаемого можно, только если это одно и то же
	// и прошлое применение удалось: неудачное могло оборваться между файлами.
	renderable := settled && rec.Status == "healthy"
	dir := p.appDir(slug)

	compose := driftObservation{key: driftObjectCompose + ":" + slug}
	composeExpected := rec.ComposeSha256
	if composeExpected == "" && renderable && !app.FromGit() {
		composeExpected = sha256Hex(app.Compose)
		compose.adopt = composeExpected
	}
	// Compose git-приложения без записанного хеша не отрисовать без клона
	// репозитория — «нет данных» до следующего применения.
	composeDisk, composeStatus := compareFile(filepath.Join(dir, "docker-compose.yml"), composeExpected, false)
	compose.record = driftRecordFor(driftObjectCompose, slug, composeStatus, settled)
	if composeStatus != driftNoBaseline {
		compose.record.ExpectedSha = composeExpected
	}
	compose.record.DiskSha = composeDisk.full
	if compose.adopt != "" && composeStatus != driftMatch {
		compose.adopt = ""
	}

	env := driftObservation{key: driftObjectEnv + ":" + slug}
	var envStatus string
	var envDisk fileDigest
	if rec.EnvSha256 != "" {
		envDisk, envStatus = compareFile(filepath.Join(dir, ".env"), rec.EnvSha256, false)
	} else if renderable {
		// Домен в отпечаток git-приложения не входит, и его смена не повод для
		// переприменения — строка APP_DOMAIN на диске законно старее желаемой.
		// Поэтому у git-приложения она выбрасывается с обеих сторон.
		dropDomain := app.FromGit()
		expected := digestReader(strings.NewReader(renderEnv(app)), dropDomain)
		envDisk, envStatus = compareFile(filepath.Join(dir, ".env"), expected.compared, dropDomain)
		if envStatus == driftMatch {
			env.adopt = envDisk.full
		}
	} else {
		envStatus = driftNoBaseline
	}
	// Хешей .env наружу нет вовсе: по хешу файла с короткими значениями их
	// подбирают перебором (ADR-0078, решение 7).
	env.record = driftRecordFor(driftObjectEnv, slug, envStatus, settled)

	return []driftObservation{compose, env}
}

// observeCaddyfile сверяет Caddyfile хоста. ok=false — прокси здесь не
// разворачивался, и сверять нечего.
func observeCaddyfile(p Paths, apps []DesiredApp, opts ProxyOptions) (driftObservation, bool) {
	path := filepath.Join(p.proxyDir(), "conf", "Caddyfile")
	obs := driftObservation{key: driftObjectCaddyfile}

	marker, markerErr := os.ReadFile(p.proxyWrittenPath())
	expected := strings.TrimSpace(string(marker))
	if markerErr != nil || !driftShaPattern.MatchString(expected) {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) && errors.Is(markerErr, os.ErrNotExist) {
			return obs, false
		}
		expected = ""
	}

	want := sha256.Sum256([]byte(renderCaddyfile(apps, opts)))
	settled := expected != "" && hex.EncodeToString(want[:]) == expected

	disk, status := compareFile(path, expected, false)
	obs.record = driftRecordFor(driftObjectCaddyfile, "", status, settled)
	if status != driftNoBaseline {
		obs.record.ExpectedSha = expected
	}
	obs.record.DiskSha = disk.full
	return obs, true
}

// driftRecordFor ставит толкование по раскладу ADR-0078, решение 5.
func driftRecordFor(object, slug, status string, settled bool) DriftRecord {
	r := DriftRecord{Object: object, Slug: slug, Status: status}
	switch status {
	case driftMismatch, driftMissing:
		r.Disposition = driftForeign
		if !settled {
			r.Disposition = driftForeignOverPending
		}
	case driftMatch:
		if !settled {
			r.Disposition = driftInTransit
		}
	}
	return r
}

// fileDigest — хеш файла целиком и хеш того, что сравнивается.
type fileDigest struct {
	full     string
	compared string
}

// compareFile читает файл потоком и сравнивает с базовой линией. Пустая
// базовая линия — «нет данных», что бы ни лежало на диске.
func compareFile(path, expected string, dropDomain bool) (fileDigest, string) {
	if expected == "" {
		return fileDigest{}, driftNoBaseline
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileDigest{}, driftMissing
	}
	if err != nil {
		return fileDigest{}, driftUnreadable
	}
	defer f.Close()
	// Каталог открывается без ошибки, а читается с ней — это тоже «не
	// прочитать», а не «пустой файл».
	if info, statErr := f.Stat(); statErr != nil || !info.Mode().IsRegular() {
		return fileDigest{}, driftUnreadable
	}
	digest := digestReader(f, dropDomain)
	if digest.full == "" {
		return fileDigest{}, driftUnreadable
	}
	if digest.compared != expected {
		return digest, driftMismatch
	}
	return digest, driftMatch
}

// digestReader считает оба хеша за один проход. Пустой full — ошибка чтения.
//
// Выброс строк APP_DOMAIN= идёт по строкам с их переводом строки: одно и то же
// правило применяется к отрисованному .env и к файлу на диске, поэтому
// расхождение в краевых случаях невозможно.
func digestReader(r io.Reader, dropDomain bool) fileDigest {
	full := sha256.New()
	compared := sha256.New()
	reader := bufio.NewReader(io.TeeReader(r, full))
	for {
		line, err := reader.ReadString('\n')
		if !(dropDomain && strings.HasPrefix(line, "APP_DOMAIN=")) {
			compared.Write([]byte(line))
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fileDigest{}
		}
	}
	return fileDigest{
		full:     hex.EncodeToString(full.Sum(nil)),
		compared: hex.EncodeToString(compared.Sum(nil)),
	}
}

// adoptBaselines закрепляет базовую линию, выведенную из желаемого.
//
// Иначе она жила бы только пока желаемое совпадает с применённым: первый же
// новый релиз до применения превращал бы «совпадает» в «нет данных».
// Закрепляется хеш файла на диске — он совпал с отрисованным, значит это
// запись агента.
func adoptBaselines(p Paths, observed []driftObservation) error {
	adopt := map[string]string{}
	for _, obs := range observed {
		if obs.adopt != "" {
			adopt[obs.key] = obs.adopt
		}
	}
	if len(adopt) == 0 {
		return nil
	}

	state := LoadApplied(p)
	changed := false
	for slug, rec := range state.Apps {
		if sha, ok := adopt[driftObjectCompose+":"+slug]; ok && rec.ComposeSha256 == "" {
			rec.ComposeSha256 = sha
			changed = true
		}
		if sha, ok := adopt[driftObjectEnv+":"+slug]; ok && rec.EnvSha256 == "" {
			rec.EnvSha256 = sha
			changed = true
		}
		state.Apps[slug] = rec
	}
	if !changed {
		return nil
	}
	return SaveApplied(p, state)
}

// loadDriftState — последнее известное по объектам. Битый или раздутый файл
// равносилен пустому: повторное «первое наблюдение» честнее застрявшей сверки.
func loadDriftState(p Paths) (map[string]string, error) {
	state := map[string]string{}
	raw, err := os.ReadFile(p.driftStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("последнее известное дрейфа не прочитано: %w", err)
	}
	if len(raw) > driftStateMaxFileBytes {
		return state, nil
	}
	var file struct {
		Objects map[string]string `json:"objects"`
	}
	if json.Unmarshal(raw, &file) != nil || file.Objects == nil {
		return state, nil
	}
	return file.Objects, nil
}

func saveDriftState(p Paths, objects map[string]string) error {
	raw, err := json.Marshal(struct {
		Objects map[string]string `json:"objects"`
	}{Objects: objects})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(p.driftStatePath(), raw, 0o600); err != nil {
		return fmt.Errorf("последнее известное дрейфа не сохранено: %w", err)
	}
	return nil
}
