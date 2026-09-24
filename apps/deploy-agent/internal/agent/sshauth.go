package agent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Перебор SSH на серверах, подключённых для развёртывания.
//
// ЗАЧЕМ. Агент развёртывания читал только логи Caddy, то есть видел ровно
// HTTP-угрозы. Получалось противоречие: платформа ЗНАЛА, что на сервере открыт
// вход по паролю (состояние sshd приезжает тем же тактом), и не видела, что в
// эту дверь стучат. Сервер, подключённый только через развёртывание, показывал
// «пароль открыт, fail2ban выключен» — и ноль попыток подбора, потому что
// читать их было некому.
//
// Агент мониторинга это давно умеет. Здесь та же логика — с той же
// дедупликацией и тем же курсором, — чтобы охват не зависел от того, каким
// способом сервер подключили.

// sshAuthLogPaths — где лежит журнал аутентификации.
//
// Debian и производные пишут в auth.log, RHEL и производные — в secure.
// Проверяем оба: агент ставится на что дадут, а гадать по /etc/os-release
// дороже, чем сделать два stat.
var sshAuthLogPaths = []string{"/var/log/auth.log", "/var/log/secure"}

// Разбор попытки входа.
//
// Три формы sshd, и все три означают одну попытку: «Failed password for root
// from …», «Failed password for invalid user admin from …», «Invalid user admin
// from …».
//
// ПОЧЕМУ ТАК СТРОГО. Счётчик адреса участвует в решении об автоматической
// блокировке: засчитать попытку чужому адресу значит дать постороннему
// закрыть чужому посетителю доступ к сайту клиента, имея только порт 22. А
// текст, который выбирает подключающийся, попадает в журнал в двух местах:
//
//   - имя пользователя: «Invalid user x from 198.51.100.7 port 1 from
//     203.0.113.5 port 22» — подставная пара стоит ЛЕВЕЕ настоящей;
//   - причина разрыва: «Received disconnect from 203.0.113.5 port 5555:11:
//     Invalid user a1 from 198.51.100.7 port 1» — сообщение о входе целиком
//     сочинено клиентом и стоит в конце строки.
//
// Поэтому два условия, и оба обязательны. Сообщение начинается СРАЗУ после
// первой метки программы в строке, и эта метка — sshd: метку пишет syslog до
// любого текста клиента, подделать её положение нельзя. Пара « from <адрес>
// port <n>» стоит В КОНЦЕ строки (sshd дописывает к «Failed password» только
// « ssh2»): жадный `(.*)` отдаёт регулярке самое правое вхождение, что бы ни
// стояло левее. Прежние версии искали слова в любом месте строки и брали
// последнее совпадение FindAll — совпадения FindAll не перекрываются, и имя
// `x from 198.51.100.7 port 1` оставляло подставную пару последней.
//
// `sshd-session` — имя, под которым пишет OpenSSH 9.8+ (Debian 13 и новее):
// без него такие серверы молча показывали бы ноль попыток подбора.
var (
	sshSyslogTagRe = regexp.MustCompile(`([\w.-]+)\[\d+\]: `)
	sshFailureRe   = regexp.MustCompile(`^(?:Failed password for|Invalid user)(.*) from ([0-9a-fA-F:.]+) port \d+(?: ssh2)?$`)
)

// parseSSHFailure — адрес и имя пользователя из строки неудачного входа.
//
// Имя — последнее слово перед « from»: брать его по слову «user» нельзя, в
// самой частой строке («Failed password for root from») этого слова нет, и
// все попытки с одного адреса схлопнулись бы в одну. У пустого имени («Invalid
// user  from …») слово пустое, и такая попытка тоже попытка.
func parseSSHFailure(line string) (ip, user string, ok bool) {
	tag := sshSyslogTagRe.FindStringSubmatchIndex(line)
	if tag == nil {
		return "", "", false
	}
	if name := line[tag[2]:tag[3]]; name != "sshd" && name != "sshd-session" {
		return "", "", false
	}
	m := sshFailureRe.FindStringSubmatch(line[tag[1]:])
	if m == nil {
		return "", "", false
	}
	before := m[1]
	return m[2], trimSSHUser(before[strings.LastIndexByte(before, ' ')+1:]), true
}

// sshAuthCursor — где мы остановились в журнале.
//
// Та же схема, что у журнала Caddy: смещение плюс отпечаток начала файла.
// Отпечаток обязателен — logrotate подменяет файл, и одно смещение после этого
// указывало бы в середину нового журнала.
type sshAuthCursor struct {
	Offset int64  `json:"offset"`
	Fp     string `json:"fp"`
	FpLen  int    `json:"fpLen"`
}

func (p Paths) sshAuthCursorPath() string {
	return filepath.Join(p.StateDir, "ssh-auth-cursor.json")
}

// CollectSSHFailures считает неудачные попытки входа с прошлого такта.
//
// Возвращает число попыток и адреса-нарушители. Пустой результат — штатное
// состояние: на закрытом сервере попыток нет вовсе.
//
// Ошибка чтения не поднимается наверх: журнал аутентификации доступен не
// каждому агенту (права, нестандартная сборка), и выкат из-за этого падать не
// должен. «Не смогли прочитать» и «попыток нет» здесь неразличимы намеренно —
// различать их значило бы поднимать тревогу о собственных правах на каждом
// такте.
func CollectSSHFailures(p Paths) (attempts int64, byIP map[string]int64) {
	attempts, byIP, next := collectSSHFailures(p)
	if next != nil {
		saveSSHAuthCursor(p, *next)
	}
	return attempts, byIP
}

// collectSSHFailures — то же без записи курсора: его сохраняет вызывающий,
// когда окно доставлено (TrafficWindow.Commit). nil — журнал не прочитан, и
// курсор трогать незачем.
func collectSSHFailures(p Paths) (attempts int64, byIP map[string]int64, next *sshAuthCursor) {
	byIP = map[string]int64{}

	path := firstExistingPath(sshAuthLogPaths)
	if path == "" {
		return 0, byIP, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, byIP, nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, byIP, nil
	}

	cursor := loadSSHAuthCursor(p)
	// Первый запуск: журнал читается с начала и содержит хоть месяц истории.
	// Отдавать это как окно в минуту нельзя — пороги сработали бы на
	// накопленном. Курсор двигаем, событий не отдаём.
	bootstrap := cursor.FpLen == 0
	start := cursor.Offset

	if bootstrap || !sameSSHAuthFile(f, cursor) || info.Size() < cursor.Offset {
		// Ротация или усечение: читаем с начала нового файла.
		start = 0
		if bootstrap {
			start = info.Size()
		}
	}

	if _, err := f.Seek(start, 0); err != nil {
		return 0, byIP, nil
	}

	// Одна попытка входа — одно событие, а не столько, сколько строк написал
	// sshd. Неудачный вход несуществующим пользователем даёт минимум две
	// строки, а с PAM и preauth — четыре: счёт по строкам завышал бы перебор
	// вчетверо.
	//
	// Ключ — пара (адрес, пользователь) в пределах окна. Секунду в ключ не
	// берём: строки одной попытки идут с разными метками времени, и с секундой
	// дедупликация не сработала бы вовсе.
	seen := map[string]bool{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	read := start

	for scanner.Scan() {
		line := scanner.Text()
		read += int64(len(line)) + 1

		ip, user, ok := parseSSHFailure(line)
		if !ok {
			continue
		}

		key := ip + "\x00" + user
		if seen[key] {
			continue
		}
		seen[key] = true

		attempts++
		byIP[ip]++
	}

	next = &sshAuthCursor{
		Offset: read,
		Fp:     sshAuthFingerprint(f),
		FpLen:  sshFingerprintLen,
	}

	if bootstrap {
		return 0, map[string]int64{}, next
	}
	return attempts, byIP, next
}

// sshFingerprintLen — сколько байт начала файла берём в отпечаток.
const sshFingerprintLen = 256

// Отпечаток снимается тем же способом, что у журнала Caddy: своя копия
// разошлась бы с ним на первой правке.
func sshAuthFingerprint(f *os.File) string {
	fp, err := fileFingerprint(f, sshFingerprintLen)
	if err != nil {
		return ""
	}
	return fp
}

func sameSSHAuthFile(f *os.File, cursor sshAuthCursor) bool {
	if cursor.Fp == "" || cursor.FpLen == 0 {
		return false
	}
	fp, err := fileFingerprint(f, int64(cursor.FpLen))
	if err != nil {
		return false
	}
	return fp == cursor.Fp
}

func loadSSHAuthCursor(p Paths) sshAuthCursor {
	var c sshAuthCursor
	raw, err := os.ReadFile(p.sshAuthCursorPath())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(raw, &c)
	return c
}

func saveSSHAuthCursor(p Paths, c sshAuthCursor) {
	raw, err := json.Marshal(c)
	if err != nil {
		return
	}
	_ = writeFileAtomic(p.sshAuthCursorPath(), raw, 0o600)
}

func firstExistingPath(paths []string) string {
	for _, path := range paths {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return ""
}

// trimSSHUser — служебные приставки sshd в имени пользователя.
//
// «for invalid user admin from …» даёт слово `admin`, а «for root from …» —
// `root`. Пустое имя sshd пишет двумя пробелами («Invalid user  from …»), и
// слово выходит пустым само. Но если пробел один, перед «from» оказывается
// слово `user`, и без отсечения безымянная попытка получила бы ключ
// «пользователь user» — отличный от той же попытки в соседней строке.
func trimSSHUser(user string) string {
	if strings.EqualFold(user, "user") {
		return ""
	}
	return user
}
