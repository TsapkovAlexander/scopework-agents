// Агент платформы развёртывания Scopework.
//
// Модель работы — pull: агент сам ходит к Scopework по исходящему HTTPS и
// забирает желаемое состояние. Scopework к серверу не подключается никогда,
// поэтому на хосте не открывается ни одного входящего порта, и агент работает
// за NAT и любым фаерволом. Это же означает, что компрометация нашей стороны
// не даёт входа на серверы клиентов — им нечего принимать.
//
// Команды:
//
//	deploy-agent enroll --url=https://scopework.ru --token=tdx_... [--dir=/etc/tracedocs/deploy]
//	deploy-agent run    --url=https://scopework.ru                 [--dir=...] [--interval=60s]
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Version подставляется при сборке: -ldflags "-X main.Version=1.2.3".
var Version = "0.0.0-dev"

const defaultDir = "/etc/tracedocs/deploy"

// Код выхода при отзыве хоста. Отдельный код нужен, чтобы systemd-юнит мог
// не перезапускать агента по кругу: отозванный хост сам собой не вернётся.
const exitRevoked = 3

// deniedStreakLimit — сколько отказов подряд агент считает настоящим отзывом.
//
// Одиночного 401 недостаточно, и это не перестраховка. 2026-08-07 платформа
// была недоступна во время выката: сначала запросы не проходили вовсе, потом
// сервер ответил отказом — и агент на хосте остановился НАСОВСЕМ, потому что
// systemd не перезапускает код 3. Обнаружилось это по неработающему сайту,
// поднялось руками по SSH. Один сбой платформы не должен гасить парк агентов.
//
// Серия обязана быть непрерывной: любой успешный проход обнуляет счётчик.
const deniedStreakLimit = 5

// heartbeatFallbackAfter — через сколько тишины запасная отметка о жизни
// отправляется сама.
//
// СЧИТАЕТСЯ ОТ ПОРОГА МОЛЧАНИЯ, А НЕ ОТ ПЕРИОДА ОПРОСА. Прежде порогом служил
// сам период (минута), и это давало лишний запрос на каждом такте: такт длится
// около 88 секунд (25 удержания плюс минута ожидания) и отметку обновляет сам,
// но горутина всё равно просыпалась через минуту после него и слала свою.
// Двa запроса там, где достаточно одного, — при том что сокращение их числа и
// было смыслом единого такта.
//
// Молчащим платформа считает хост, от которого нет вестей ПЯТЬ минут (0191,
// 0223). Две с половиной — половина этого срока: на спокойном хосте, который
// платформа опрашивает раз в пять минут, отметка успевает уйти дважды за
// период, и запас до ложной тревоги остаётся двукратным.
const heartbeatFallbackAfter = 150 * time.Second

// deniedWindow — сколько времени отказы должны идти подряд, чтобы считаться
// отзывом.
//
// СРОК, А НЕ ЧИСЛО ПОПЫТОК. Прежний порог «пять отказов» подбирался под
// фиксированную минуту опроса и означал пять минут. С тех пор интервал
// назначает платформа (Ш-5), и во время выката он равен пяти секундам: те же
// пять отказов укладываются в полминуты — меньше, чем длится выкат самой
// платформы, ради которого защита и появилась.
//
// Пять минут: платформа успевает вернуться после выката или перезапуска базы,
// а настоящий отзыв откладывается на те же пять минут, что для операции
// «сервер отключён» ничего не значит.
const deniedWindow = 5 * time.Minute

// nextDeniedStreak — новое значение счётчика отказов после одного прохода.
//
// Отдельной функцией, потому что это единственное место, где решается судьба
// агента на хосте, а проверить его внутри цикла опроса нечем.
func nextDeniedStreak(prev int, err error) int {
	switch {
	case err == nil:
		// Успех обнуляет: серия обязана быть непрерывной.
		return 0
	case errors.Is(err, agent.ErrClockSkew):
		// Расхождение часов — не отказ платформы, а неисправность хоста, и
		// чинится она на хосте. Приближать агента к остановке нельзя: он
		// выключился бы навсегда там, где достаточно включить NTP.
		return 0
	case errors.Is(err, agent.ErrUnauthorized):
		return prev + 1
	default:
		// Сетевой сбой — это отсутствие ответа, а не отказ. Приближать к
		// остановке он не должен: иначе сутки без связи с платформой
		// заканчивались бы «отзывом» на ровном месте.
		return 0
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "enroll":
		if err := cmdEnroll(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
			os.Exit(1)
		}
	case "run":
		if err := cmdRun(os.Args[2:]); err != nil {
			if errors.Is(err, agent.ErrUnauthorized) {
				fmt.Fprintln(os.Stderr, "хост отозван или ключ больше не признаётся; агент остановлен")
				os.Exit(exitRevoked)
			}
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		// Признаёт ли платформа личность, которая уже лежит на диске.
		//
		// Нужна установщику: до неё он решал «сервер уже подключён» по одному
		// наличию файла и на хосте с отозванной личностью молча ничего не
		// делал — агент поднимался со старым ключом, сразу получал отказ и
		// умирал, а в панели сервер вечно «ожидает установки».
		//
		// Коды выхода: 0 — признан, 3 — не признан (нужен enroll --force),
		// 1 — проверить не удалось (сеть, лежащая платформа). Третий случай
		// отделён намеренно: перерегистрировать хост из-за недоступной
		// платформы значит потерять связь с уже работающим сервером.
		if err := cmdVerify(os.Args[2:]); err != nil {
			if errors.Is(err, agent.ErrUnauthorized) {
				fmt.Fprintln(os.Stderr, "платформа не признаёт ключ этого сервера")
				os.Exit(exitRevoked)
			}
			fmt.Fprintf(os.Stderr, "verify: %v\n", err)
			os.Exit(1)
		}
	case "docker-proxy":
		// Привилегированная половина агента: слушает свой сокет от root и
		// пропускает демону только то, что агенту разрешено (ADR-0083).
		if err := cmdDockerProxy(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "docker-proxy: %v\n", err)
			os.Exit(1)
		}
	case "journal":
		os.Exit(cmdJournal(os.Args[2:], os.Stdout, os.Stderr))
	case "policy":
		os.Exit(cmdPolicy(os.Args[2:], os.Stdout, os.Stderr))
	case "version":
		os.Exit(cmdVersion(os.Args[2:], os.Stdout, os.Stderr))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Scopework deploy agent %s

  enroll --url=<base> --token=<token> [--dir=%s] [--force]
        Создаёт пару ключей и регистрирует сервер по одноразовому токену.
        --force перезаписывает ключ, который платформа больше не признаёт.

  verify --url=<base> [--dir=%s]
        Признаёт ли платформа ключ, лежащий на диске. Коды выхода:
        0 — признан, 3 — не признан, 1 — проверить не удалось.

  run    --url=<base> [--dir=%s] [--interval=60s]
        Периодически отмечается и забирает желаемое состояние.

  docker-proxy --listen=<sock> --allow-bind=<dir>[,<dir>] [--upstream=/var/run/docker.sock]
        Прокси сокета Docker: пропускает демону перечисленные вызовы и
        отбивает привилегии в теле. Запускается от root отдельным юнитом,
        сам агент работает от своего пользователя и видит только этот сокет.

%s`, Version, defaultDir, defaultDir, defaultDir, localUsage())
}

// validateBaseURL требует https.
//
// По этому адресу уезжают подписанные запросы и приезжают переменные
// приложений — пароль базы и ключи. По http они пошли бы открытым текстом,
// и вся модель «секреты отдаются агенту по TLS» держалась бы на том, что
// оператор не опечатался при установке.
//
// Исключение — только localhost: там TLS нет по определению, а прогон нужен.
func validateBaseURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("нужен --url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--url не разбирается: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return fmt.Errorf("--url должен начинаться с https:// (получено %q)", raw)
}

func identityPath(dir string) string {
	return filepath.Join(dir, "identity.json")
}

// readEnrollToken достаёт одноразовый токен установки.
//
// Через stdin, а НЕ через флаг. Аргументы командной строки видны в
// /proc/<pid>/cmdline и в выводе `ps` любому пользователю хоста, и на время
// установки токен был бы доступен всем — включая контейнеры с pid: host.
// Перехвативший его регистрирует собственного агента со своим ключом и по
// подписанным запросам получает всё желаемое состояние проекта: пароль базы,
// ключ шифрования, токены реестров.
//
// Переменная окружения лучше флага (/proc/<pid>/environ читает только
// владелец и root), но хуже stdin: она наследуется дочерними процессами и
// всплывает в дампах. Поэтому она — только запасной путь для окружений без
// удобного stdin.
func readEnrollToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv("TRACEDOCS_TOKEN")); token != "" {
		return token, nil
	}

	// Ограничиваем чтение: stdin — недоверенный вход, и «токен» на гигабайт
	// не должен съесть память.
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать токен из stdin: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("нужен токен установки: передайте его в stdin или в TRACEDOCS_TOKEN")
	}
	return token, nil
}

// cmdVerify — один подписанный запрос текущей личностью.
//
// Спрашиваем отметку о жизни, а не желаемое состояние: она дешевле, ничего не
// меняет и проверяет ровно то, что нужно, — признаёт ли платформа этот ключ.
func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	url := fs.String("url", "", "базовый адрес Scopework")
	dir := fs.String("dir", defaultDir, "каталог состояния агента")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Состояние доверия — вслух при старте (ADR-0082, задача С1.3). Пока ключ
	// выпуска не вшит, агент применяет то, что приехало по TLS, и молчаливое
	// «проверок нет» и было тем, из-за чего задача попала в план.
	if agent.ReleaseSignatureRequired() {
		fmt.Printf("подпись выпуска проверяется: доверенных ключей %d\n",
			len(agent.TrustedReleaseKeys()))
	} else {
		fmt.Fprintln(os.Stderr,
			"ВНИМАНИЕ: подпись выпуска НЕ проверяется — в этой сборке агента нет "+
				"доверенного ключа. Обновления принимаются по сумме, которую даёт та же "+
				"сторона, что и файл.")
	}

	if err := validateBaseURL(*url); err != nil {
		return err
	}

	id, err := agent.LoadIdentity(identityPath(*dir))
	if err != nil {
		return err
	}

	client := agent.NewClient(*url, Version)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Heartbeat(ctx, id, ""); err != nil {
		return err
	}
	fmt.Printf("сервер признан; отпечаток %s\n", id.Fingerprint())
	return nil
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	url := fs.String("url", "", "базовый адрес Scopework")
	dir := fs.String("dir", defaultDir, "каталог состояния агента")
	// Переустановка на хосте, чью личность платформа больше не признаёт:
	// прежний ключ бесполезен, и держаться за него — значит оставить сервер
	// неподключаемым. Ставит флаг install.sh, и только убедившись, что текущая
	// личность отвергнута (см. подкоманду verify).
	force := fs.Bool("force", false, "перезаписать существующий ключ")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Состояние доверия — вслух при старте (ADR-0082, задача С1.3). Пока ключ
	// выпуска не вшит, агент применяет то, что приехало по TLS, и молчаливое
	// «проверок нет» и было тем, из-за чего задача попала в план.
	if agent.ReleaseSignatureRequired() {
		fmt.Printf("подпись выпуска проверяется: доверенных ключей %d\n",
			len(agent.TrustedReleaseKeys()))
	} else {
		fmt.Fprintln(os.Stderr,
			"ВНИМАНИЕ: подпись выпуска НЕ проверяется — в этой сборке агента нет "+
				"доверенного ключа. Обновления принимаются по сумме, которую даёт та же "+
				"сторона, что и файл.")
	}

	if err := validateBaseURL(*url); err != nil {
		return err
	}

	tokenValue, err := readEnrollToken()
	if err != nil {
		return err
	}
	token := &tokenValue

	path := identityPath(*dir)

	// Повторный enroll затёр бы существующий ключ, и сервер перестал бы
	// узнавать этот хост. Отказываемся явно — кроме явного --force.
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("агент уже зарегистрирован (%s); для переустановки отзовите хост и удалите файл, либо запустите с --force", path)
	}

	// Ключ берём из отложенного файла, если прошлая попытка его оставила.
	//
	// ЗАЧЕМ. Регистрация не атомарна: RPC на сервере коммитит (ключ записан,
	// хост активен, токен сожжён), а ответ теряется — сеть, таймаут, холодный
	// старт платформы. Раньше ключ жил только в памяти процесса и исчезал
	// вместе с ним: на хосте пусто, в базе публичный ключ без пары и без
	// токена, повторить нечем. Единственным выходом было пересоздать хост.
	//
	// Теперь пара пишется на диск ДО отправки. Повтор той же командой идёт с
	// тем же токеном и тем же ключом — сервер (0228) узнаёт по этой тройке
	// собственный незавершённый заход и отвечает тем же успехом.
	id, reused, err := loadOrCreateIdentity(*dir, enrollBinding(*token, *url))
	if err != nil {
		return err
	}
	if reused {
		fmt.Fprintf(os.Stderr, "повторяем незавершённую регистрацию, отпечаток %s\n", id.Fingerprint())
	}

	client := agent.NewClient(*url, Version)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := client.Enroll(ctx, *token, id); err != nil {
		// Отложенный ключ намеренно НЕ удаляем: если ответ потерялся уже после
		// коммита, повтор этой же командой — единственный способ доехать.
		return err
	}

	// Ключ сохраняем только после успешной регистрации: иначе на диске остался
	// бы ключ, которого сервер не знает, и повторный enroll был бы заблокирован
	// проверкой выше.
	if err := agent.SaveIdentity(path, id); err != nil {
		return fmt.Errorf("регистрация прошла, но ключ не сохранён: %w", err)
	}
	// Отложенный убираем только теперь: пока он есть, повтор считает
	// регистрацию незавершённой.
	os.Remove(pendingIdentityPath(*dir))
	os.Remove(pendingBindingPath(*dir))

	fmt.Printf("зарегистрировано; отпечаток %s\n", id.Fingerprint())
	return nil
}

// pendingIdentityPath — ключ отправленной, но не подтверждённой регистрации.
func pendingIdentityPath(dir string) string {
	return filepath.Join(dir, "identity.pending.json")
}

// pendingBindingPath — к какой попытке относится отложенный ключ.
func pendingBindingPath(dir string) string {
	return filepath.Join(dir, "identity.pending.owner")
}

// enrollBinding — отпечаток пары «токен + адрес платформы».
//
// Сам токен на диск не кладём: отложенный ключ переживает неудачную попытку и
// может пролежать сколько угодно, а одноразовый токен в открытом виде на чужом
// хосте — это ровно то, чего установщик избегает, пряча его от `ps`.
func enrollBinding(token, baseURL string) string {
	sum := sha256.Sum256([]byte(token + "\n" + baseURL))
	return hex.EncodeToString(sum[:])
}

// loadOrCreateIdentity возвращает ключ незавершённой попытки либо новый.
//
// ПОЧЕМУ ПОВТОР ПРИВЯЗАН К ТОКЕНУ. Отложенный ключ нужен ровно для одного
// случая: ответ на регистрацию потерялся, и повтор ТЕМ ЖЕ токеном должен
// доехать. Переиспользовать его для другой попытки нельзя, и вот почему.
// Первая попытка провалилась (сеть, неверный токен); человек удаляет хост в
// панели, создаёт новый и копирует новую команду. Со старым ключом сервер
// отвечает «отпечаток уже занят» — строка отозванного хоста из базы не
// исчезает, — а человек видит отказ при исправном токене и не имеет никакой
// подсказки: лечится это удалением файла, о котором нигде не сказано.
//
// Непрочитавшийся отложенный файл (обрезан на записи, испорчен) не повод
// падать: генерируем новый. Хуже от этого не станет — исходная ситуация ровно
// такая же, как до появления отложенных ключей.
func loadOrCreateIdentity(dir, binding string) (agent.Identity, bool, error) {
	pending := pendingIdentityPath(dir)
	bindingPath := pendingBindingPath(dir)

	if saved, err := os.ReadFile(bindingPath); err == nil &&
		strings.TrimSpace(string(saved)) == binding {
		if id, err := agent.LoadIdentity(pending); err == nil && id.PublicKey != "" {
			return id, true, nil
		}
	}

	id, err := agent.NewIdentity()
	if err != nil {
		return agent.Identity{}, false, err
	}
	if err := agent.SaveIdentity(pending, id); err != nil {
		return agent.Identity{}, false, fmt.Errorf("ключ не удалось записать до отправки: %w", err)
	}
	// Привязка пишется ПОСЛЕ ключа: обратный порядок оставил бы после обрыва
	// привязку к ключу, которого нет, и повтор пошёл бы с чужой парой.
	if err := os.WriteFile(bindingPath, []byte(binding), 0o600); err != nil {
		return agent.Identity{}, false, fmt.Errorf("привязку регистрации не удалось записать: %w", err)
	}
	return id, false, nil
}

// startHeartbeat шлёт отметку о жизни по собственному расписанию.
//
// Раньше отметка была первым шагом цикла, и это работало, пока цикл был
// коротким. С тяжёлыми стеками он таким быть перестал: ожидание подъёма
// Supabase — до пятнадцати минут по заданию шаблона, и всё это время хост не
// отчитывался бы. Снаружи это выглядит как выключенный сервер: панель
// показывает «нет связи», срабатывают оповещения, кто-то идёт разбираться —
// а на хосте в этот момент штатно скачиваются образы.
//
// Отдельная горутина отвязывает «я жив» от «я закончил работу». Признаком
// отзыва хоста при этом остаётся отказ на запросе желаемого состояния: он
// приходит в тот же цикл и так же возвращает ErrUnauthorized.
// lastHeartbeat — последний успешный ответ heartbeat, для самообновления в
// основном цикле: подменять бинарь из горутины heartbeat нельзя — она может
// сработать посреди применения стека.
func startHeartbeat(
	ctx context.Context,
	client *agent.Client,
	id agent.Identity,
	lastHeartbeat *atomic.Pointer[agent.HeartbeatResponse],
	proxyError *atomic.Pointer[string],
	lastTick *atomic.Int64,
	lastSelfBeat *atomic.Int64,
) {
	go func() {
		// Проверяем чаще периода: отметка нужна не по расписанию, а когда её
		// давно не было. Раз в десять секунд — дёшево, потому что почти всегда
		// это проверка числа в памяти без единого запроса.
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			// ЗАПАСНОЙ КАНАЛ, А НЕ ОСНОВНОЙ (Ш-3).
			//
			// В устойчивом состоянии отметку несёт сам такт — он приходит
			// каждую минуту и обновляет last_seen_at заодно со всем прочим.
			// Отдельный запрос в этот момент был бы вторым обращением на ровном
			// месте, а сокращение их числа — весь смысл единого такта.
			//
			// Но такт бывает долгим: ожидание подъёма Supabase доходит до
			// пятнадцати минут по заданию шаблона. Всё это время хост не
			// отчитывался бы, и снаружи это выглядит как выключенный сервер:
			// панель показывает «нет связи», срабатывают оповещения, кто-то
			// идёт разбираться — а на хосте штатно скачиваются образы.
			// Считаем от ПОЗДНЕЙШЕГО из двух событий: доехавшего такта и
			// собственной прошлой отправки.
			//
			// Без второго слагаемого горутина, однажды перешагнув порог, шлёт
			// отметку на КАЖДОМ срабатывании тикера — то есть раз в десять
			// секунд, пока такт не доедет. На спокойном хосте, где платформа
			// назначила опрос раз в пять минут, это двадцать шесть запросов за
			// цикл вместо одного: заявленная экономия превращается в расход
			// впятеро больше прежнего.
			last := lastTick.Load()
			if own := lastSelfBeat.Load(); own > last {
				last = own
			}
			if time.Since(time.Unix(last, 0)) < heartbeatFallbackAfter {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					continue
				}
			}

			// Состояние прокси кладёт основной цикл, а отправляет эта
			// горутина: цикл может быть занят подъёмом стека минутами, а
			// сообщить о том, что ни один домен не публикуется, надо сразу.
			reason := ""
			if p := proxyError.Load(); p != nil {
				reason = *p
			}
			if hb, err := client.Heartbeat(ctx, id, reason); err != nil && ctx.Err() == nil {
				// Не повод останавливаться: сетевой сбой лечится следующей
				// попыткой, а отзыв хоста заметит основной цикл.
				fmt.Fprintf(os.Stderr, "отметка о жизни: %v\n", err)
			} else if err == nil {
				lastHeartbeat.Store(&hb)
				lastSelfBeat.Store(time.Now().Unix())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// tick — один проход: забрать желаемое состояние, привести хост к нему и
// отчитаться о каждом релизе.
//
// Порядок важен. Прокси настраивается ДО подъёма стеков: Caddy должен уже
// слушать 80-й порт, когда Let's Encrypt придёт проверять владение доменом.
// Если поднять сначала приложение, первая проверка ACME придётся на закрытый
// порт, и выпуск сертификата отложится до следующей попытки.
// applyDesired приводит хост к желаемому состоянию.
//
// Вынесено из tick отдельной функцией ради одного: всё, что МЕНЯЕТ хост,
// должно вызываться в одном месте и под одним условием. Пока эти шаги стояли в
// теле такта вперемешку со сбором отчётов, пропустить их на первом проходе
// было нечем — а первый проход идёт с пустым состоянием и снёс бы все стеки.
func applyDesired(
	ctx context.Context,
	client *agent.Client,
	id agent.Identity,
	paths agent.Paths,
	opts agent.ProxyOptions,
	apps []agent.DesiredApp,
	registries []agent.RegistryCredential,
	proxyError *atomic.Pointer[string],
) {
	// Уборку делаем ДО настройки прокси: снятый стек не должен оставаться в
	// конфиге, иначе Caddy будет держать маршрут в никуда и продлевать
	// сертификат для домена, который больше не обслуживается.
	if removed := agent.Cleanup(ctx, paths, apps); len(removed) > 0 {
		fmt.Printf("сняты стеки: %v\n", removed)
	}

	// Входы в реестры — ДО прокси и стеков: и caddy, и приложения тянут
	// образы, а авторизованный лимит Docker Hub решает проблему квоты на
	// подсеть провайдера. Неудача входа не останавливает цикл: публичные
	// образы скачаются и так.
	if results := agent.EnsureRegistryLogins(ctx, paths, registries); len(results) > 0 {
		if err := client.ReportRegistryLogins(ctx, id, results); err != nil {
			fmt.Fprintf(os.Stderr, "отчёт о входах в реестры: %v\n", err)
		}
	}

	if err := agent.EnsureProxy(ctx, paths, apps, opts); err != nil {
		// Прокси не поднялся — стеки всё равно применяем: приложение,
		// работающее без публикации наружу, лучше, чем не работающее вовсе.
		//
		// Но молчать об этом нельзя: пока прокси лежит, НИ ОДИН домен хоста не
		// отвечает, а приложения при этом честно `healthy`. Причина уходит на
		// платформу отметкой о жизни и показывается в интерфейсе.
		fmt.Fprintf(os.Stderr, "прокси: %v\n", err)
		reason := err.Error()
		proxyError.Store(&reason)
	} else {
		ok := ""
		proxyError.Store(&ok)
	}

	// Ход применения уезжает тем же подписанным каналом отчёта, что и итог,
	// только со статусом applying: сервер обновляет подробности релиза, но не
	// пишет событие в аудит и не даёт запоздавшему прогрессу перекрыть финал.
	// Хвост вывода уже затёрт внутри Apply — здесь только доставка.
	progress := func(releaseID, phase, output string) {
		if err := client.Report(ctx, id, releaseID, "applying",
			map[string]any{"phase": phase, "output": output}); err != nil {
			// Потерянный кадр прогресса — не причина трогать выкат: следующий
			// уйдёт через несколько секунд.
			fmt.Fprintf(os.Stderr, "отчёт о ходе выката: %v\n", err)
		}
	}

	// Пока идёт применение, вердикт образа — apply_in_progress (ADR-0091,
	// решение 6). Только вокруг Apply: самовосстановление эталон не переснимает.
	agent.WorkloadsApplyBegin()
	for _, res := range agent.Apply(ctx, paths, apps, progress) {
		if err := client.Report(ctx, id, res.ReleaseID, res.Status, res.Detail); err != nil {
			fmt.Fprintf(os.Stderr, "отчёт по релизу %s: %v\n", res.ReleaseID, err)
		}
		if res.Status == "healthy" {
			fmt.Printf("релиз %s применён\n", res.ReleaseID)
		} else {
			fmt.Fprintf(os.Stderr, "релиз %s не применён: %v\n", res.ReleaseID, res.Detail["error"])
		}
	}
	agent.WorkloadsApplyEnd()

}

// ЕДИНЫЙ ТАКТ (Ш-3). Состояние приходит аргументом, отчёты уезжают возвращённым
// значением: и то, и другое едет ОДНИМ запросом, который делает цикл вызывающего.
// Раньше здесь было шесть отдельных обращений к платформе, каждое со своей
// проверкой подписи и защитой от повторов, — 8 640 запросов в сутки с хоста при
// том, что полезной работы в большинстве тактов нет.
//
// Состояние на такт старше отчётов: его агент получил в конце прошлого цикла.
// Задержка компенсируется интервалом, который платформа же и назначает
// (nextPollSeconds): пока на хосте есть незавершённая работа, следующий такт
// идёт через пять секунд, а не через минуту.
func tick(
	ctx context.Context,
	client *agent.Client,
	id agent.Identity,
	paths agent.Paths,
	opts agent.ProxyOptions,
	state agent.DesiredState,
	// haveState — в последнем ответе платформы было желаемое состояние.
	//
	// БЕЗ ЭТОГО ПРИЗНАКА ПЕРВЫЙ ТАКТ СНОСИТ ХОСТ. Состояние теперь приезжает
	// ответом на такт, то есть в конце цикла, и первый проход идёт с нулевым
	// значением. Пустой список приложений — ЛЕГАЛЬНОЕ состояние со смыслом
	// «снять всё»: Cleanup снимает каждый стек из applied.json командой
	// `docker compose down`, а EnsureProxy пишет Caddyfile без единого домена.
	// То есть перезапуск службы, ребут хоста и КАЖДОЕ самообновление агента
	// (оно перезапускает процесс через exec) погасили бы все стеки клиента и
	// все его домены. Тома при этом целы, но восстановление — полный
	// передеплой с git clone и docker build, то есть минуты простоя.
	//
	// Отличать «состояния ещё не было» от «пришло пустое» обязательно, и
	// проверкой `len(state.Apps) == 0` этого не сделать.
	haveState bool,
	// healthChecks — владелец разрешил проверять доступность доменов (0237).
	healthChecks bool,
	proxyError *atomic.Pointer[string],
	lastHeartbeat *atomic.Pointer[agent.HeartbeatResponse],
	gate *agent.ReportGate,
	queue *agent.ReportQueue,
	// legacy — обмен идёт отдельными ручками: номер отчёта не выделяется,
	// нести его некуда (ADR-0077, решение 1).
	legacy bool,
) (agent.TickRequest, tickDelivery) {
	report := agent.TickRequest{
		AgentVersion: Version,
		// Режим снимается каждый такт с ЖИВОГО процесса, а не читается из
		// файла установки: файл говорит, как хост ставили, а не как он
		// работает сейчас.
		PrivilegeMode: agent.DetectPrivilegeMode(),
		// Просим платформу подождать, если работы нет (Ш-4). Ответ придёт в
		// момент, когда человек нажмёт кнопку, — а не на следующем такте.
		HoldSeconds: agent.TickHoldSeconds,
	}
	var delivery tickDelivery

	// Политика сервера и локальный журнал (ADR-0095): решение на такт, приход
	// состояния — в журнал до применения.
	plan := hostControl.beginTick(&report, lastHeartbeat.Load(), state, haveState)

	// Номер резервируется В НАЧАЛЕ такта: сигналы, возникшие в этом такте,
	// получают его ключ ещё до сборки секции.
	number := reserveReportNumber(paths, legacy)
	apps := state.Apps
	// Блокировка адресов приезжает вместе с состоянием и применяется ко всем
	// доменам хоста (0204). opts — копия, менять её здесь безопасно: список
	// живёт ровно один цикл, как и остальное желаемое состояние.
	opts.DenyIPs = state.DenyIPs
	opts.PlatformSubdomainBase = state.PlatformSubdomainBase

	// До первого ответа платформы хост не трогаем: ни уборки, ни прокси, ни
	// применения. Отчёты при этом собираются и уезжают обычным порядком —
	// платформа увидит хост в его настоящем виде уже на этом такте.
	if haveState && plan.Apply {
		// СВЕРКА ДРЕЙФА (ADR-0078) — здесь, ДО applyDesired: сверять надо диск
		// в том виде, в каком его оставили между тактами, а не после того, как
		// агент сам его переписал. Под тем же условием, что и применение: без
		// желаемого состояния не отличить наше изменение в пути от чужой
		// правки, а правку до первого ответа никто и не перезапишет.
		observeDrift(paths, opts, apps, queue, number)
		applyDesired(ctx, client, id, paths, opts, apps, state.Registries, proxyError)
		hostControl.stateApplied()
	} else if plan.BaselineDrift {
		// Политика не даёт применять: сверка только с базовой линией
		// applied.json, желаемое не передаётся — новой линии агент не пишет.
		observeDrift(paths, opts, nil, queue, number)
	}

	// Здоровье опрашивается на каждом цикле, а не только после выката.
	// Успешный выкат ничего не говорит о том, что происходит через неделю:
	// упавший сервис должен быть замечен, даже если разворачивали его давно.
	health := agent.CheckHealth(ctx, paths, plan.HealthApps(paths, apps))
	healthHash := agent.PayloadHash(health)
	if gate.Allow("health", healthHash, time.Now(), agent.HealthReportMaxAge) {
		report.Health = agent.HealthItems(health)
		delivery.health = &gateMark{hash: healthHash, at: time.Now()}
	}

	/*
	 * Проба хранилища копий (ADR-0046, решение 7). Хранилище отваливается тихо:
	 * сменили ключ, закрыли порт, кончилась квота, истёк внутренний сертификат.
	 * Узнать об этом в ночь, когда копия понадобилась, — то же самое, что не
	 * иметь копий.
	 *
	 * Отметка ставится ДО отправки, в отличие от остальных отчётов: там она
	 * защищает от потери отчёта при сетевом сбое, а здесь — от повторной ЗАПИСИ
	 * в чужой бакет. Неудачный такт стоит нам пропущенной пробы, а клиенту —
	 * лишнего запроса каждую минуту.
	 */
	/*
	 * Метка просьбы участвует в ключе гейта: сменилась — гейт пропускает пробу
	 * немедленно, тем же приёмом, что и осмотр сервера. Иначе человек, только
	 * что подключивший хранилище, ждал бы результата до часа и всё это время
	 * видел бы «подключено», хотя с ЕГО сервера доступа может не быть вовсе.
	 */
	/*
	 * Ключ хранилища приезжает ОДИН РАЗ и живёт дальше на этом диске: платформа
	 * его у себя затирает, как только все живые агенты подтвердят получение.
	 * Поэтому здесь состояние достраивается сохранённым ключом, а подтверждение
	 * уходит ровно на том такте, когда ключ приехал новым.
	 */
	if plan.Storage && state.ObjectStorage != nil {
		resolved, accepted := agent.ResolveStorageKey(paths, *state.ObjectStorage)
		state.ObjectStorage = &resolved
		if accepted {
			report.StorageKeyAck = resolved.KeyFingerprint
		}
	}

	if plan.Storage && state.ObjectStorage != nil && state.ObjectStorage.SecretKey != "" &&
		gate.Allow("storage", "probe:"+state.ObjectStorage.ProbeRequestedAt, time.Now(), agent.StorageProbeMaxAge) {
		gate.Mark("storage", "probe:"+state.ObjectStorage.ProbeRequestedAt, time.Now())
		if err := agent.ProbeObjectStorage(ctx, *state.ObjectStorage, id.Fingerprint()); err != nil {
			report.Storage = &agent.StorageProbeReport{OK: false, Error: err.Error()}
		} else {
			report.Storage = &agent.StorageProbeReport{OK: true}
		}
	}

	// Самовосстановление — ПОСЛЕ отчёта: платформа должна узнать о падении
	// раньше, чем агент начнёт его чинить. Иначе сервис, падающий и
	// поднимаемый каждую ночь, снаружи неотличим от работающего без сбоев.
	if err := recoverUnderPolicy(ctx, plan, paths, apps, health); err != nil {
		fmt.Fprintf(os.Stderr, "восстановление: %v\n", err)
	}

	// Осмотр сервера — по запросу человека (0210), не по расписанию: состав
	// хоста меняется редко, а перечислять чужие системы фоном каждую минуту
	// незачем.
	if hb := lastHeartbeat.Load(); hb != nil {
		if hb.InventoryRequestedAt != "" && plan.Inventory {
			if err := agent.RunInventory(ctx, client, id, paths, Version, hb.InventoryRequestedAt); err != nil {
				fmt.Fprintf(os.Stderr, "осмотр сервера: %v\n", err)
			}
		}
		// Задание с параметрами: снять слепок стека или перенести данные в том
		// (0211). Не больше одного за цикл — перенос гигабайтов и снятие
		// слепка одновременно нам ни к чему.
		if hb.Task != nil {
			if err := hostControl.runTask(ctx, client, id, paths, *hb.Task, apps, state.ObjectStorage); err != nil {
				fmt.Fprintf(os.Stderr, "задание %s: %v\n", hb.Task.Kind, err)
			}
		}
	}

	// Трафик — агрегаты access-лога с прошлого цикла (0187). Сырой лог хост
	// не покидает; неудача доставки не трогает цикл — курсоры журналов
	// двигаются только после того, как платформа окно приняла (exchange), и
	// следующий такт прочитает те же строки.
	if window, err := agent.CollectTrafficWindow(paths); err != nil {
		fmt.Fprintf(os.Stderr, "сбор трафика: %v\n", err)
	} else {
		delivery.window = window
		traffic, threat, truncated := window.Items, window.Threat, window.Truncated
		report.Traffic = agent.TrafficSection(traffic, truncated)
		// Тихое окно уходит не каждую минуту: пустая строка в threat_snapshots
		// — это 1440 записей в сутки с хоста, из которых полезны единицы.
		// Совсем не слать нельзя: платформа закрывает тревогу и шлёт «отбой»
		// именно по окну без срабатываний.
		//
		// Разобранные строки придержанных окон переносятся в следующее
		// отправленное: курсор придержанного окна двигается, и без переноса
		// счётчик «разобрано N запросов за сутки» на панели занижался бы в
		// разы. И взятое из запаса, и отложенное в запас фиксируется только
		// по исходу доставки — иначе неудачный такт терял бы запас или считал
		// бы строки дважды.
		if threat != nil {
			due := gate.Allow("threat", "quiet", time.Now(), agent.QuietThreatMaxAge)
			if agent.ThreatWorthSending(threat) || due {
				taken := gate.TakePendingParsed()
				threat.Totals.Parsed += taken
				report.Threat = agent.ThreatSection(threat, truncated)
				if report.Threat != nil {
					gate.Mark("threat", "quiet", time.Now())
					delivery.takenParsed = taken
				} else {
					// Пустое окно не отправляем вовсе — счётчик возвращается в
					// запас и уедет со следующим непустым.
					delivery.heldParsed = threat.Totals.Parsed
				}
			} else {
				delivery.heldParsed = threat.Totals.Parsed
			}
		}
	}

	// Список развёрнутого — В КОНЦЕ цикла, после уборки и применения: он должен
	// отражать состояние хоста уже с учётом этого прохода, иначе подтверждение
	// удаления опаздывало бы ровно на один цикл.
	// nil означает «состояние прочитать не удалось». Отправлять в этом случае
	// нечего: пустой список сервер понял бы как «на хосте ничего нет» и
	// завершил бы удаление приложений, которые на самом деле работают.
	if present := agent.PresentSlugs(paths); present != nil {
		// Отсев не применяется, пока на хосте есть что снимать.
		//
		// Список развёрнутого — единственный канал подтверждения удаления, и
		// приложение, которого на хосте нет ВОВСЕ (создано и не развёрнуто,
		// каталог снят раньше), список не меняет: отпечаток прежний, и
		// подтверждение придержалось бы до пяти минут вместо минуты. Пока в
		// желаемом состоянии есть снимаемые приложения, отчёт идёт каждый такт.
		pendingRemoval := false
		for _, app := range apps {
			if !app.ShouldRun() {
				pendingRemoval = true
				break
			}
		}
		presenceHash := agent.PayloadHash(present)
		if pendingRemoval || gate.Allow("presence", presenceHash, time.Now(), agent.PresenceReportMaxAge) {
			report.Presence = agent.PresenceSection(present)
			delivery.presence = &gateMark{hash: presenceHash, at: time.Now()}
		}
	}

	// Состояние хоста — в тот же такт. Раздел мониторинга серверов получает его
	// без второго агента и без «добавить сервер» руками.
	report.Metrics = agent.CollectHostMetrics(ctx)
	report.Posture = agent.CollectHostPosture(ctx)
	// Проверки доступности — только с разрешения владельца: каждая из них
	// запрос к боевому приложению раз в такт.
	if healthChecks {
		report.Checks = agent.CollectHealthChecks(ctx, apps)
	}

	// Состояние прокси кладём в отчёт здесь же: раньше его забирала горутина
	// отметки о жизни, а теперь оно едет тем же тактом.
	if p := proxyError.Load(); p != nil {
		report.ProxyError = *p
	}

	hostControl.addJournalReport(&report, gate)

	// Секция отчёта — последней: к этому моменту в очереди всё, что такт успел
	// в неё поставить.
	attachReport(&report, queue, number)
	// Нагрузки — после report: их бюджет считается от остального тела такта
	// целиком (ADR-0091, решение 9).
	agent.WorkloadsAttach(&report)

	return report, delivery
}

// tickDelivery — что из собранного за такт фиксируется только по исходу
// доставки (ADR-0077, решение 4).
type tickDelivery struct {
	window agent.TrafficWindow
	// takenParsed — счётчик придержанных окон, вложенный в отправленное окно
	// угроз. Окно угроз не принято — счётчик возвращается в запас.
	takenParsed int64
	// heldParsed — разобранные строки окна, придержанного в этом такте. В запас
	// уходят, только если курсор сдвинут: иначе строки прочитаются снова.
	heldParsed int64
	// health и presence — отметки гейта отчётов, вложенных в такт. Ставятся по
	// исходу доставки: отметка при сборке засчитала бы сетевой сбой доставкой,
	// и следующий отчёт придержался бы до срока гейта (reportgate.go, Allow).
	health   *gateMark
	presence *gateMark
}

// gateMark — отметка гейта, отложенная до исхода доставки.
type gateMark struct {
	hash string
	at   time.Time
}

// observeDrift ставит сигналы дрейфа в очередь ключом такта number.
//
// Сбой сверки такт не роняет: применение и отчёты важнее сигнала, который
// повторится следующим тактом. В журнал — только текст ошибки, содержимого
// файлов в нём нет. Последнее известное фиксируется лишь после того, как
// сигналы легли в очередь: иначе потерянная запись очереди потеряла бы и
// событие.
func observeDrift(
	paths agent.Paths,
	opts agent.ProxyOptions,
	apps []agent.DesiredApp,
	queue *agent.ReportQueue,
	number *agent.ReportNumber,
) {
	if number == nil {
		return
	}
	records, commit, err := agent.ObserveDrift(paths, apps, opts, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "сверка дрейфа: %v\n", err)
		return
	}
	if len(records) > 0 {
		if err := queue.Enqueue(number.Epoch, number.Seq, records); err != nil {
			fmt.Fprintf(os.Stderr, "сверка дрейфа: сигналы не поставлены в очередь: %v\n", err)
			return
		}
	}
	if err := commit(); err != nil {
		fmt.Fprintf(os.Stderr, "сверка дрейфа: %v\n", err)
	}
}

// reserveReportNumber — номер отчёта такта или nil, если номера нет.
func reserveReportNumber(paths agent.Paths, legacy bool) *agent.ReportNumber {
	if legacy {
		return nil
	}
	n, err := agent.ReserveReportNumber(paths)
	if err != nil {
		// Такт уходит без секции report: пропуск номера платформа переживёт,
		// а номер, выданный дважды после рестарта, выглядел бы откатом.
		fmt.Fprintf(os.Stderr, "номер отчёта: %v\n", err)
		return nil
	}
	return &n
}

func attachReport(report *agent.TickRequest, queue *agent.ReportQueue, number *agent.ReportNumber) {
	if number == nil {
		return
	}
	section := queue.Section(*number)
	report.Report = &section
}

// exchange отправляет такт и по исходу фиксирует то, что фиксируется только
// после доставки: курсоры журналов, счётчик разобранных строк, квитанции и
// очередь отчёта.
//
// Отметки гейта здоровья и списка развёрнутого — тоже здесь, по принятой
// секции: при сборке такта они засчитывали сетевой сбой доставкой.
func exchange(
	ctx context.Context,
	client *agent.Client,
	id agent.Identity,
	report agent.TickRequest,
	delivery tickDelivery,
	gate *agent.ReportGate,
	queue *agent.ReportQueue,
	legacy *bool,
) (agent.TickResponse, error) {
	var resp agent.TickResponse
	var outcome agent.TickSectionsOutcome
	var err error
	// sectionsKnown — исход секций окна известен: такт получил 2xx либо
	// секции ушли отдельными ручками, каждая со своим ответом.
	sectionsKnown := false

	if *legacy {
		outcome, resp.DesiredState, err = legacyExchange(ctx, client, id, report)
		sectionsKnown = true
	} else {
		resp, err = client.Tick(ctx, id, report)
		switch {
		case err == nil:
			outcome = resp.SectionsOutcome(report)
			sectionsKnown = true
			if report.Report != nil {
				queue.Delivered(*report.Report, agent.ParseReportAck(resp.ReportAck))
			}
			agent.WorkloadsDelivered(report, resp)
		case errors.Is(err, agent.ErrEndpointUnknown):
			// Номер этого такта не доехал: старая платформа секцию не увидит,
			// а квитанция уедет первым тактом новой.
			noteUndelivered(queue, report, err)
			fmt.Fprintln(os.Stderr,
				"платформа не знает единого такта — перехожу на прежние ручки")
			*legacy = true
			outcome, resp.DesiredState, err = legacyExchange(ctx, client, id, report)
			sectionsKnown = true
		default:
			noteUndelivered(queue, report, err)
		}
	}

	if sectionsKnown && outcome.WindowDelivered(report) {
		delivery.window.Commit()
		gate.AddPendingParsed(delivery.heldParsed)
	}
	if !outcome.Threat {
		gate.AddPendingParsed(delivery.takenParsed)
	}
	if sectionsKnown && outcome.Health && delivery.health != nil {
		gate.Mark("health", delivery.health.hash, delivery.health.at)
	}
	if sectionsKnown && outcome.Presence && delivery.presence != nil {
		gate.Mark("presence", delivery.presence.hash, delivery.presence.at)
	}
	return resp, err
}

func noteUndelivered(queue *agent.ReportQueue, report agent.TickRequest, err error) {
	if report.Report == nil {
		return
	}
	queue.NoteUndelivered(
		agent.ReportNumber{Epoch: report.Report.Epoch, Seq: report.Report.Seq},
		agent.UndeliveredReasonFor(err))
}

// legacyExchange — прежний обмен шестью ручками.
//
// Живёт ради одного случая: платформу откатили назад, а агент уже обновился до
// единого такта. Отчёты уезжают по отдельности, состояние забирается своим
// запросом, отметку о жизни несёт горутина — то есть ровно так, как было до
// Ш-3. Неудача отдельного отчёта такт не роняет: статистика догонит следующим
// окном, а невыполненный выкат не догонит никогда.
func legacyExchange(
	ctx context.Context,
	client *agent.Client,
	id agent.Identity,
	report agent.TickRequest,
) (agent.TickSectionsOutcome, agent.DesiredState, error) {
	outcome, err := client.ReportTickSections(ctx, id, report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "отчёты такта: %v\n", err)
	}
	state, err := client.DesiredState(ctx, id)
	return outcome, state, err
}

// adoptState заменяет желаемое состояние ответом такта — только принятым
// (ADR-0093, решение 4). Непринятое клиент обнуляет, но ошибкой не делает, и
// замена по одному «ошибки нет» превратила бы любой отказ проверки подписи в
// «снять всё». Вынесено из цикла cmdRun, чтобы это условие проверялось тестом.
func adoptState(state agent.DesiredState, haveState bool, resp agent.TickResponse, err error) (agent.DesiredState, bool) {
	if err == nil && resp.DesiredState.Accepted {
		return resp.DesiredState, true
	}
	return state, haveState
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	url := fs.String("url", "", "базовый адрес Scopework")
	dir := fs.String("dir", defaultDir, "каталог состояния агента")
	workDir := fs.String("work-dir", agent.DefaultPaths().WorkDir, "каталог стеков и прокси")
	acmeEmail := fs.String("acme-email", "", "адрес для уведомлений Let's Encrypt")
	localTLS := fs.Bool("local-tls", false, "сертификаты от внутреннего центра Caddy (только для локального прогона)")
	interval := fs.Duration("interval", 60*time.Second, "период опроса")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Состояние доверия — вслух при старте (ADR-0082, задача С1.3). Пока ключ
	// выпуска не вшит, агент применяет то, что приехало по TLS, и молчаливое
	// «проверок нет» и было тем, из-за чего задача попала в план.
	if agent.ReleaseSignatureRequired() {
		fmt.Printf("подпись выпуска проверяется: доверенных ключей %d\n",
			len(agent.TrustedReleaseKeys()))
	} else {
		fmt.Fprintln(os.Stderr,
			"ВНИМАНИЕ: подпись выпуска НЕ проверяется — в этой сборке агента нет "+
				"доверенного ключа. Обновления принимаются по сумме, которую даёт та же "+
				"сторона, что и файл.")
	}
	// Подпись желаемого состояния — так же вслух (ADR-0093, решение 2). Битые
	// корни — не причина выходить: агент продолжает такты и каждым докладывает
	// отказ, а молча упавшая служба выглядела бы на платформе выключенным
	// сервером.
	switch roots, err := agent.StateRootsStatus(); {
	case err != nil:
		fmt.Fprintf(os.Stderr,
			"ВНИМАНИЕ: %v. Никакое желаемое состояние применяться не будет: стеки "+
				"остаются как есть, каждый такт докладывает trust_roots_invalid.\n", err)
	case len(roots) > 0:
		fmt.Printf("подпись состояния проверяется: корней %d\n", len(roots))
	default:
		fmt.Fprintln(os.Stderr,
			"ВНИМАНИЕ: подпись состояния НЕ проверяется — в этой сборке агента нет "+
				"корней. Состояние применяется без подписи, как раньше.")
	}

	if err := validateBaseURL(*url); err != nil {
		return err
	}
	// Int63n паникует при неположительном аргументе, а джиттер считается как
	// interval/10 — при слишком малом интервале агент падал бы с паникой.
	// Заодно защищаемся от опроса, который завалит и сервер, и хост.
	if *interval < 10*time.Second {
		return fmt.Errorf("--interval не может быть меньше 10s (получено %s)", *interval)
	}

	id, err := agent.LoadIdentity(identityPath(*dir))
	if err != nil {
		return fmt.Errorf("агент не зарегистрирован: %w", err)
	}

	paths := agent.Paths{StateDir: *dir, WorkDir: *workDir}
	client := agent.NewClient(*url, Version)
	// Защёлки против отката подписанного состояния: без каталога агент с
	// корнями не примет ни одного пакета.
	client.UseStateDir(paths.StateDir)

	// Конфиг docker (в нём учётные данные реестров после login) живёт в
	// каталоге состояния агента, а не в /root: systemd-юнит закрывает
	// домашние каталоги (ProtectHome), и писать туда docker не смог бы.
	// Значение уходит в окружение каждой команды docker через dockerEnv.
	dockerCfg := filepath.Join(*dir, "docker")
	if err := os.MkdirAll(dockerCfg, 0o700); err != nil {
		return fmt.Errorf("не удалось создать каталог конфига docker: %w", err)
	}
	// MkdirAll не трогает права УЖЕ существующего каталога: если он однажды
	// создан с 0755, права такими и останутся, и учётные данные реестров
	// защищал бы только режим самого config.json.
	if err := os.Chmod(dockerCfg, 0o700); err != nil {
		return fmt.Errorf("не удалось закрыть каталог конфига docker: %w", err)
	}
	if err := os.Setenv("DOCKER_CONFIG", dockerCfg); err != nil {
		return err
	}

	// Ключи репозиториев с прошлых запусков: обычно они удаляются сразу после
	// работы с git, но SIGKILL и OOM отменяют отложенное удаление.
	agent.PurgeGitKeys(paths)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("агент запущен, отпечаток %s, период %s\n", id.Fingerprint(), *interval)

	// Политика сервера и локальный журнал (ADR-0095) — до первого такта.
	hostControl = newLocalControl(ctx, *dir)

	// Успешное обновление подтверждаем: версия совпала с целью маркера —
	// защита от повторных попыток на эту цель больше не нужна.
	agent.ClearUpdateMarker(paths, Version)

	// Отметка о жизни идёт своим чередом, независимо от того, сколько длится
	// применение: тяжёлый стек не должен выглядеть как выключенный сервер.
	var lastHeartbeat atomic.Pointer[agent.HeartbeatResponse]
	// Состояние прокси: пишет основной цикл, читает горутина отметки о жизни.
	var proxyError atomic.Pointer[string]
	// Когда такт в последний раз доехал до платформы: по нему горутина отметки
	// решает, нужна ли она вообще.
	var lastTick atomic.Int64
	// Когда горутина отправляла отметку сама — иначе, перешагнув порог, она
	// слала бы её на каждом срабатывании тикера.
	var lastSelfBeat atomic.Int64
	startHeartbeat(ctx, client, id, &lastHeartbeat, &proxyError, &lastTick, &lastSelfBeat)

	// Отсев отчётов, которые ничего не сообщают: в устойчивом состоянии
	// здоровье и список развёрнутого не меняются такт за тактом, а окно угроз
	// на тихом хосте пусто. См. reportgate.go.
	gate := agent.NewReportGate()
	// Очередь отчёта: квитанции недоставленных тактов и сигналы дрейфа
	// (ADR-0077). Живёт на диске и переживает рестарт и самообновление.
	queue := agent.LoadReportQueue(paths)
	// Сигналы нагрузок (ADR-0091): выборка раз в 60 с и поток docker events в фоне.
	agent.StartWorkloads(ctx, paths)
	defer agent.StopWorkloads()

	// Сколько отказов подряд считать отзывом хоста. См. deniedStreakLimit.
	denied := 0
	// Когда началась текущая серия отказов «не признан».
	var deniedSince time.Time

	// Желаемое состояние приезжает ответом на такт, то есть в конце цикла.
	// Первый цикл идёт с пустым: применять нечего, зато отчёт о развёрнутом
	// уедет сразу и платформа увидит хост в его настоящем виде.
	var state agent.DesiredState
	// Интервал назначает платформа (Ш-5): пока на хосте есть незавершённая
	// работа, следующий такт идёт через секунды, а не через минуту. До первого
	// ответа держимся флага.
	wait := *interval
	// Платформа старше агента: обмен идёт прежними шестью ручками.
	legacy := false
	// Есть ли желаемое состояние в последнем ответе. См. параметр haveState у
	// tick: без этого признака первый проход снёс бы все стеки хоста.
	haveState := false
	// Проверки доступности: до первого ответа платформы не знаем, разрешены ли
	// они, и не делаем. Молчаливое «по умолчанию да» означало бы запрос к
	// боевому приложению вопреки выключателю, который владелец уже щёлкнул.
	healthChecks := false

	for {
		report, delivery := tick(ctx, client, id, paths, agent.ProxyOptions{
			ACMEEmail: *acmeEmail,
			LocalTLS:  *localTLS,
			// forward_auth (0188) ходит туда же, куда агент — за состоянием.
			PlatformBaseURL: client.BaseURL,
		}, state, haveState, healthChecks, &proxyError, &lastHeartbeat, gate, queue, legacy)

		// ОДИН запрос на весь такт: отчёты уезжают, состояние приезжает.
		//
		// Откат на прежние шесть ручек — на случай, когда платформу откатили
		// назад, а агент уже обновился. Штатно этого не бывает (бинарь агент
		// берёт с неё же), но откат выката — обычное дело, и превращать его в
		// остановку всего парка агентов нельзя.
		resp, err := exchange(ctx, client, id, report, delivery, gate, queue, &legacy)
		if err == nil && !legacy {
			lastHeartbeat.Store(&resp.HeartbeatResponse)
			// Отметка о жизни доехала тактом — запасной горутине работы нет.
			lastTick.Store(time.Now().Unix())
			if resp.NextPollSeconds > 0 {
				wait = time.Duration(resp.NextPollSeconds) * time.Second
			}
			healthChecks = resp.HealthChecksEnabled
		}
		if err == nil {
			hostControl.received(resp, gate, legacy)
		}
		// Порядок приёма: подпись проверена в клиенте (Accepted), политика
		// хоста решает на следующем такте (beginTick → agent.Decide). Отказ
		// любой из двух — не применять: непринятое состояние сюда не попадает,
		// а принятое политика может не пустить в применение.
		state, haveState = adoptState(state, haveState, resp, err)

		denied = nextDeniedStreak(denied, err)
		switch {
		case err == nil:
			deniedSince = time.Time{}
		case errors.Is(err, agent.ErrUnauthorized):
			// Серия считается ПО ВРЕМЕНИ, а не по числу попыток.
			//
			// Порог в пять отказов был подобран под фиксированную минуту
			// опроса — «пять попыток раз в минуту это пять минут». Теперь
			// интервал назначает платформа, и во время выката он равен пяти
			// секундам: те же пять отказов укладываются в полминуты, после
			// чего агент выключается насовсем с кодом, который systemd не
			// перезапускает. Окно выката самой платформы, когда её ручки
			// отвечают отказом, длится дольше.
			if deniedSince.IsZero() {
				deniedSince = time.Now()
			}
			if time.Since(deniedSince) >= deniedWindow {
				return err
			}
			// Интервал возвращаем флаговый: долбить лежащую платформу каждые
			// пять секунд — верный способ её не поднять.
			wait = *interval
			fmt.Fprintf(os.Stderr,
				"сервер не признал агента (%s из %s); если это сбой платформы, "+
					"следующая попытка через %s\n",
				time.Since(deniedSince).Round(time.Second), deniedWindow, wait)
		default:
			// Сетевые сбои — обычное дело; продолжаем по расписанию, не
			// раскручивая частоту, чтобы не добить лежащий сервер.
			//
			// Состояние при этом СОХРАНЯЕТСЯ прежним, а не обнуляется: пустое
			// означало бы «на хосте не должно быть ничего», и обрыв связи снёс
			// бы все стеки клиента.
			//
			// Интервал возвращаем флаговый: назначенные платформой пять секунд
			// осмысленны, пока она отвечает, а на лежащей они превращаются в
			// двенадцать бесполезных попыток в минуту.
			wait = *interval
			fmt.Fprintf(os.Stderr, "такт: %v\n", err)
		}

		// Самообновление — МЕЖДУ циклами, когда никакой стек не применяется.
		// exec замещает процесс на месте: PID тот же, systemd ничего не
		// перезапускает, следующий цикл идёт уже новой версией.
		if hb := lastHeartbeat.Load(); hb != nil {
			if binPath, ok := hostControl.selfUpdate(ctx, client, paths, *hb); ok {
				fmt.Printf("перезапуск после обновления до %s\n", hb.TargetAgentVersion)
				// exec не убивает дочерние процессы: `docker events` пережил бы
				// его и жил рядом с потоком новой версии.
				agent.StopWorkloads()
				if err := syscall.Exec(binPath, os.Args, os.Environ()); err != nil {
					// Бинарь уже подменён, но процесс остался старым: доживёт
					// до перезапуска службы. Молчать нельзя.
					fmt.Fprintf(os.Stderr, "самообновление: exec не удался: %v\n", err)
					agent.StartWorkloads(ctx, paths)
				}
			}
		}

		// Джиттер до 10% периода: иначе десятки агентов, запущенные одним
		// плейбуком, будут бить в ingest одновременно. Считается от
		// назначенного платформой интервала, а не от флага, и от неположительного
		// значения защищаемся здесь же — Int63n на нуле паникует.
		jitter := time.Duration(0)
		if wait/10 > 0 {
			jitter = time.Duration(rand.Int63n(int64(wait) / 10))
		}
		select {
		case <-ctx.Done():
			fmt.Println("остановка по сигналу")
			return nil
		case <-time.After(wait + jitter):
		// Падение контейнера будит такт раньше срока, не чаще раза в минуту
		// (ADR-0091, решение 5).
		case <-agent.WorkloadsWake():
		}
	}
}
