package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Вход в реестры образов.
//
// Docker Hub ограничивает анонимные загрузки на подсеть провайдера — соседи по
// хостингу выбирают квоту за нас, и на первом боевом прогоне даже caddy не
// скачался. Авторизованный лимит кратно выше, а приватные образы без входа
// недоступны вовсе. Токены приезжают вместе с желаемым состоянием по
// подписанному запросу и попадают только в конфиг docker (DOCKER_CONFIG в
// каталоге состояния агента, 0700).
//
// Вход выполняется не на каждом цикле, а по отметкам — как applied.json для
// стеков. Повторный `docker login` раз в минуту был бы не только шумом: Hub
// временно блокирует за серию неудачных входов, и агент с отозванным токеном
// сам загнал бы себя в блокировку.

const registryLoginsFileName = "registry-logins.json"

// Пауза перед повтором после неудачного входа. Минутный цикл агента давал бы
// 60 попыток в час — Docker Hub блокирует раньше.
const registryRetryDelay = 15 * time.Minute

// RegistryCredential — учётные данные одного реестра из желаемого состояния.
type RegistryCredential struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

// RegistryLoginResult — итог попытки входа, уходит на сервер.
type RegistryLoginResult struct {
	Registry string
	OK       bool
	Detail   string
}

// RegistryLoginRecord — отметка о последней попытке входа в один реестр.
type RegistryLoginRecord struct {
	// Отпечаток пары (пользователь, токен) вместе с адресом: ротация токена
	// обязана приводить к повторному входу.
	CredHash    string    `json:"cred_hash"`
	Status      string    `json:"status"` // ok | failed
	LastAttempt time.Time `json:"last_attempt"`
}

// RegistryLoginState — отметки по всем реестрам хоста.
type RegistryLoginState struct {
	Registries map[string]RegistryLoginRecord `json:"registries"`
}

func registryLoginsPath(p Paths) string { return filepath.Join(p.StateDir, registryLoginsFileName) }

// LoadRegistryLogins читает отметки. Отсутствие или повреждение файла — не
// ошибка: худшее последствие — один лишний вход.
func LoadRegistryLogins(p Paths) RegistryLoginState {
	state := RegistryLoginState{Registries: map[string]RegistryLoginRecord{}}

	raw, err := os.ReadFile(registryLoginsPath(p))
	if err != nil {
		return state
	}
	if err := json.Unmarshal(raw, &state); err != nil || state.Registries == nil {
		return RegistryLoginState{Registries: map[string]RegistryLoginRecord{}}
	}
	return state
}

// SaveRegistryLogins сохраняет отметки атомарно.
func SaveRegistryLogins(p Paths, state RegistryLoginState) error {
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// 0600: сам токен в отметках не хранится, только его хеш, но каталог
	// приватный, и расширять права незачем.
	return writeFileAtomic(registryLoginsPath(p), data, 0o600)
}

// registryCredHash — отпечаток учётных данных. Поля разделяются нулевым
// байтом, чтобы сдвиг границы ("ab","c") против ("a","bc") менял результат.
func registryCredHash(c RegistryCredential) string {
	h := sha256.New()
	h.Write([]byte(c.Registry))
	h.Write([]byte{0})
	h.Write([]byte(c.Username))
	h.Write([]byte{0})
	h.Write([]byte(c.Token))
	return hex.EncodeToString(h.Sum(nil))
}

// needsRegistryLogin решает, нужно ли входить. Возвращает причину — для лога.
func needsRegistryLogin(rec RegistryLoginRecord, found bool, credHash string, now time.Time) (bool, string) {
	if !found {
		return true, "ещё не входили"
	}
	if rec.CredHash != credHash {
		return true, "учётные данные сменились"
	}
	if rec.Status == "failed" {
		if now.Sub(rec.LastAttempt) < registryRetryDelay {
			return false, "недавняя неудача, ждём паузу"
		}
		return true, "повтор после неудачи"
	}
	return false, "уже вошли"
}

// safeRegistryHost — имя хоста реестра с необязательным портом. Ничего, что
// docker мог бы принять за флаг или адрес со схемой.
var safeRegistryHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

// safeRegistryUsername — без пробелов и управляющих символов; не начинается с
// дефиса, чтобы не читаться как флаг.
var safeRegistryUsername = regexp.MustCompile(`^[^-\s[:cntrl:]][^\s[:cntrl:]]{0,199}$`)

// metadataHost — адреса, по которым реестра не бывает, а токены облачного
// инстанса бывают: 169.254.0.0/16 — link-local, там висит эндпоинт метаданных
// (169.254.169.254), и его же имя в GCP. Приватные диапазоны намеренно
// разрешены: самохостовый реестр во внутренней сети — законный сценарий.
func isMetadataHost(registry string) bool {
	host := registry
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	return host == "metadata.google.internal" || strings.HasPrefix(host, "169.254.")
}

// validateRegistryCredential — агент живёт на чужой машине и обязан не
// доверять входу второй раз: сервер уже проверял, но одна ошибка там не
// должна превращаться в инъекцию аргументов здесь.
func validateRegistryCredential(c RegistryCredential) error {
	if !safeRegistryHost.MatchString(c.Registry) {
		return fmt.Errorf("недопустимый адрес реестра: %q", c.Registry)
	}
	if isMetadataHost(c.Registry) {
		return fmt.Errorf("адрес метаданных не может быть реестром: %q", c.Registry)
	}
	if !safeRegistryUsername.MatchString(c.Username) {
		return fmt.Errorf("недопустимое имя пользователя реестра %s", c.Registry)
	}
	if c.Token == "" || len(c.Token) > 4096 {
		return fmt.Errorf("пустой или неправдоподобно длинный токен для %s", c.Registry)
	}
	for _, r := range c.Token {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("управляющие символы в токене для %s", c.Registry)
		}
	}
	return nil
}

// registryLoginArgs собирает аргументы docker login.
//
// docker.io уходит БЕЗ аргумента сервера: учётные данные Docker Hub живут в
// конфиге docker под служебным ключом index.docker.io, и именно его CLI
// выбирает, когда сервер не указан. Явный `docker login docker.io` положил бы
// запись под другим ключом, и pull её не нашёл бы.
func registryLoginArgs(c RegistryCredential) []string {
	args := []string{"login"}
	if c.Registry != "" && c.Registry != "docker.io" {
		args = append(args, c.Registry)
	}
	return append(args, "-u", c.Username, "--password-stdin")
}

// Предел одной попытки входа: реестр может висеть, а цикл агента — нет.
const registryLoginTimeout = 60 * time.Second

// Предел на ВСЕ входы за один цикл.
//
// Одного таймаута на реестр мало: входы идут последовательно и до настройки
// прокси и подъёма стеков. Десяток недоступных адресов — и агент десять минут
// не доходит до приложений, то есть сайты не обновляются, а сертификаты не
// продлеваются. Сервер ограничивает число реестров, но агент живёт на чужой
// машине и обязан не зависеть от того, что ограничение на той стороне цело.
const registryLoginBudget = 3 * time.Minute

// EnsureRegistryLogins приводит входы в реестры к желаемому набору.
//
// Возвращает результаты только реальных попыток — по ним сервер обновляет
// last_used_at и пишет аудит. Пропущенные по отметкам реестры в результаты
// не попадают: иначе агент бомбардировал бы сервер «успехами» каждую минуту.
//
// Реестры, исчезнувшие из желаемого состояния, разлогиниваются: удалённый в
// интерфейсе токен не должен продолжать жить в конфиге docker на хосте.
func EnsureRegistryLogins(ctx context.Context, p Paths, creds []RegistryCredential) []RegistryLoginResult {
	state := LoadRegistryLogins(p)
	var results []RegistryLoginResult
	now := time.Now()
	changed := false

	desired := make(map[string]bool, len(creds))
	for _, cred := range creds {
		desired[cred.Registry] = true
	}

	// Разлогин идёт ПЕРВЫМ и вне бюджета на входы: операция чисто локальная
	// (правка config.json), сети не касается, и откладывать её из-за
	// недоступного реестра значило бы оставлять отозванный токен на диске.
	if removeStaleLogins(ctx, state, desired) {
		changed = true
	}

	// Бюджет на входы: они идут последовательно, по 60 секунд на реестр, и
	// ДО настройки прокси и подъёма стеков.
	loginCtx, cancel := context.WithTimeout(ctx, registryLoginBudget)
	defer cancel()

	for _, cred := range creds {
		if err := validateRegistryCredential(cred); err != nil {
			// Мусор не идёт в docker, но отметка ставится: без неё агент
			// повторял бы отказ и отчёт о нём на каждом цикле.
			fmt.Fprintf(os.Stderr, "реестр %s: %v\n", cred.Registry, err)
			hash := registryCredHash(cred)
			rec, found := state.Registries[cred.Registry]
			if should, _ := needsRegistryLogin(rec, found, hash, now); !should {
				desired[cred.Registry] = true
				continue
			}
			state.Registries[cred.Registry] = RegistryLoginRecord{
				CredHash: hash, Status: "failed", LastAttempt: now,
			}
			results = append(results, RegistryLoginResult{
				Registry: cred.Registry, OK: false, Detail: err.Error(),
			})
			changed = true
			continue
		}

		hash := registryCredHash(cred)
		rec, found := state.Registries[cred.Registry]
		should, reason := needsRegistryLogin(rec, found, hash, now)
		if !should {
			continue
		}

		err := dockerLogin(loginCtx, cred)
		record := RegistryLoginRecord{CredHash: hash, Status: "ok", LastAttempt: now}
		result := RegistryLoginResult{Registry: cred.Registry, OK: true, Detail: reason}
		if err != nil {
			record.Status = "failed"
			result.OK = false
			result.Detail = err.Error()
			fmt.Fprintf(os.Stderr, "вход в реестр %s: %v\n", cred.Registry, err)
		} else {
			fmt.Printf("вход в реестр %s выполнен (%s)\n", cred.Registry, reason)
		}
		state.Registries[cred.Registry] = record
		results = append(results, result)
		changed = true
	}

	if changed {
		if err := SaveRegistryLogins(p, state); err != nil {
			// Не сохранили отметки — на следующем цикле будет лишний вход.
			// Неприятно, но не разрушительно.
			fmt.Fprintf(os.Stderr, "не удалось сохранить отметки о входах: %v\n", err)
		}
	}

	return results
}

// removeStaleLogins разлогинивает реестры, исчезнувшие из желаемого состояния.
//
// Отметка снимается ТОЛЬКО после успешного выхода: иначе неудачный `docker
// logout` тихо оставил бы отозванные учётные данные в config.json навсегда, а
// агент считал бы, что убрал их. Повтор на следующем цикле безвреден — выход
// локальный и идемпотентный.
//
// Единственное исключение — ключ, не проходящий проверку имени хоста: его
// нельзя передать docker, и держать такую запись незачем. Появиться она может
// только правкой файла отметок вручную.
func removeStaleLogins(ctx context.Context, state RegistryLoginState, desired map[string]bool) bool {
	changed := false

	for registry := range state.Registries {
		if desired[registry] {
			continue
		}

		if !safeRegistryHost.MatchString(registry) {
			fmt.Fprintf(os.Stderr, "отметка о входе с недопустимым именем реестра удалена без выхода: %q\n",
				tail(registry, 80))
			delete(state.Registries, registry)
			changed = true
			continue
		}

		if err := dockerLogout(ctx, registry); err != nil {
			fmt.Fprintf(os.Stderr, "выход из реестра %s: %v\n", registry, err)
			continue
		}

		fmt.Printf("выход из реестра %s: учётные данные удалены на сервере\n", registry)
		delete(state.Registries, registry)
		changed = true
	}

	return changed
}

func dockerLogin(ctx context.Context, cred RegistryCredential) error {
	loginCtx, cancel := context.WithTimeout(ctx, registryLoginTimeout)
	defer cancel()

	cmd := exec.CommandContext(loginCtx, "docker", registryLoginArgs(cred)...)
	// Токен уходит через stdin, а не через аргумент: аргументы видны в списке
	// процессов любому пользователю хоста.
	cmd.Stdin = strings.NewReader(cred.Token)
	cmd.Env = dockerEnv()

	if out, err := cmd.CombinedOutput(); err != nil {
		// Вывод обрезаем и не включаем stdin: токена в нём нет, но и хвост
		// лога с деталями учётной записи на сервер целиком не нужен.
		return fmt.Errorf("docker login: %w: %s", err, tail(string(out), 300))
	}
	return nil
}

func dockerLogout(ctx context.Context, registry string) error {
	args := []string{"logout"}
	if registry != "" && registry != "docker.io" {
		args = append(args, registry)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = dockerEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker logout: %w: %s", err, tail(string(out), 300))
	}
	return nil
}
