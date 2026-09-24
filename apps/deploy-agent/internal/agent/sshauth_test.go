package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// Одна попытка входа — одно событие, а не столько строк, сколько написал sshd.
//
// ДЕФЕКТ, ОТ КОТОРОГО ЗАЩИЩАЕТ. Неудачный вход несуществующим пользователем
// даёт минимум две строки («Invalid user admin from …» и «Failed password for
// invalid user admin from …»), а с PAM и preauth — четыре. Счёт по строкам
// завышал бы перебор вчетверо, и обычная фоновая долбёжка выглядела бы
// катастрофой.
func TestSSHFailuresDeduplicated(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")

	const lines = `Aug  9 03:00:01 srv sshd[1]: Invalid user admin from 203.0.113.7 port 51234
Aug  9 03:00:01 srv sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2
Aug  9 03:00:02 srv sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2 [preauth]
Aug  9 03:00:05 srv sshd[2]: Failed password for root from 203.0.113.7 port 51240 ssh2
Aug  9 03:00:09 srv sshd[3]: Failed password for root from 198.51.100.4 port 22 ssh2
Aug  9 03:00:11 srv sshd[4]: Accepted publickey for deploy from 198.51.100.9 port 22 ssh2
`

	if err := os.WriteFile(log, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	// Подменяем список путей на наш временный файл.
	saved := sshAuthLogPaths
	sshAuthLogPaths = []string{log}
	defer func() { sshAuthLogPaths = saved }()

	p := Paths{StateDir: dir, WorkDir: dir}

	// Первый вызов — знакомство с файлом: событий не отдаём, иначе месяц
	// накопленной истории уехал бы как окно в минуту.
	if attempts, _ := CollectSSHFailures(p); attempts != 0 {
		t.Fatalf("первое чтение отдало %d попыток, ожидалось 0", attempts)
	}

	// Дописываем те же строки — теперь они новые для курсора.
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(lines); err != nil {
		t.Fatal(err)
	}
	f.Close()

	attempts, byIP := CollectSSHFailures(p)

	// Три попытки: (203.0.113.7, admin), (203.0.113.7, root), (198.51.100.4, root).
	// Успешный вход по ключу событием не является.
	if attempts != 3 {
		t.Fatalf("попыток %d, ожидалось 3: %v", attempts, byIP)
	}
	if byIP["203.0.113.7"] != 2 {
		t.Fatalf("с 203.0.113.7 засчитано %d, ожидалось 2", byIP["203.0.113.7"])
	}
	if byIP["198.51.100.4"] != 1 {
		t.Fatalf("с 198.51.100.4 засчитано %d, ожидалось 1", byIP["198.51.100.4"])
	}
	if _, ok := byIP["198.51.100.9"]; ok {
		t.Fatal("удачный вход по ключу засчитан как попытка перебора")
	}

	// Повторный вызов без новых строк — ноль: курсор не даёт пересчитать.
	if again, _ := CollectSSHFailures(p); again != 0 {
		t.Fatalf("повторное чтение отдало %d попыток, ожидалось 0", again)
	}
}

// Подделать адрес-нарушитель через имя пользователя нельзя.
//
// Имя выбирает подключающийся, и пробелы sshd в нём сохраняет. Разбор по
// первому совпадению засчитывал попытку адресу, который атакующий вписал сам.
// Это не только искажение панели: счётчик адреса участвует в решении об
// автоматической блокировке, и посторонний мог закрыть чужому посетителю
// доступ к сайту клиента, имея лишь доступ к порту 22.
func TestSSHFailureIPCannotBeSpoofed(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")

	saved := sshAuthLogPaths
	sshAuthLogPaths = []string{log}
	defer func() { sshAuthLogPaths = saved }()

	if err := os.WriteFile(log, []byte("знакомство\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Paths{StateDir: dir, WorkDir: dir}
	CollectSSHFailures(p) // первый вызов только двигает курсор

	// Атакующий 203.0.113.5 вписывает чужой адрес в имя пользователя.
	const spoof = "Aug  9 03:00:01 srv sshd[1]: Invalid user x from 198.51.100.7 from 203.0.113.5 port 22\n"
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(spoof)
	f.Close()

	_, byIP := CollectSSHFailures(p)

	if byIP["198.51.100.7"] != 0 {
		t.Fatalf("попытка засчитана подставному адресу: %v", byIP)
	}
	if byIP["203.0.113.5"] != 1 {
		t.Fatalf("настоящий адрес не засчитан: %v", byIP)
	}
}

// Подмена с портом в имени пользователя.
//
// «Последнее совпадение» регулярки из FindAll — не то же, что «последняя пара в
// строке»: совпадения не перекрываются. Имя `x from 198.51.100.7 port 1`
// съедает слово перед настоящим « from», и второе совпадение не находится
// вовсе — последним оказывается подставной адрес.
func TestSSHFailureIPCannotBeSpoofedWithPortInUsername(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")

	saved := sshAuthLogPaths
	sshAuthLogPaths = []string{log}
	defer func() { sshAuthLogPaths = saved }()

	if err := os.WriteFile(log, []byte("знакомство\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Paths{StateDir: dir, WorkDir: dir}
	CollectSSHFailures(p)

	const spoof = "Aug  9 03:00:01 srv sshd[1]: Invalid user x from 198.51.100.7 port 1 from 203.0.113.5 port 22\n" +
		"Aug  9 03:00:01 srv sshd[1]: Failed password for invalid user x from 198.51.100.7 port 1 from 203.0.113.5 port 22 ssh2\n" +
		// sshd пишет пустое имя двумя пробелами: такая попытка тоже попытка.
		"Aug  9 03:00:02 srv sshd[2]: Invalid user  from 203.0.113.6 port 40022\n"
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(spoof); err != nil {
		t.Fatal(err)
	}
	f.Close()

	attempts, byIP := CollectSSHFailures(p)

	if byIP["198.51.100.7"] != 0 {
		t.Fatalf("попытка засчитана подставному адресу: %v", byIP)
	}
	// Две строки одной попытки — одно событие.
	if byIP["203.0.113.5"] != 1 {
		t.Fatalf("настоящий адрес не засчитан ровно одной попыткой: %v", byIP)
	}
	if byIP["203.0.113.6"] != 1 || attempts != 2 {
		t.Fatalf("попытка с пустым именем потеряна: attempts=%d %v", attempts, byIP)
	}
}

// Подмена текстом, который пишет в журнал сам клиент.
//
// Причину разрыва присылает подключившийся, и sshd кладёт её в строку как есть:
// «Received disconnect from <настоящий> port N:11: <текст клиента>». Текст вида
// `Invalid user a1 from 198.51.100.7 port 1` делал строку похожей на попытку
// входа с чужого адреса. Та же форма уже обошла awk-разбор.
func TestSSHFailureMessageMustFollowSyslogTag(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "auth.log")

	saved := sshAuthLogPaths
	sshAuthLogPaths = []string{log}
	defer func() { sshAuthLogPaths = saved }()

	if err := os.WriteFile(log, []byte("знакомство\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Paths{StateDir: dir, WorkDir: dir}
	CollectSSHFailures(p)

	const lines = "" +
		"Aug  9 03:00:01 srv sshd[123]: Received disconnect from 203.0.113.5 port 5555:11: Invalid user a1 from 198.51.100.7 port 1 [preauth]\n" +
		// После входа [preauth] не дописывается — конец строки сам по себе не защита.
		"Aug  9 03:00:01 srv sshd[123]: Received disconnect from 203.0.113.5 port 5555:11: bye Invalid user a1 from 198.51.100.7 port 1\n" +
		"Aug  9 03:00:01 srv sshd[1]: Connection closed by invalid user x Invalid user y from 198.51.100.7 port 1 203.0.113.5 port 5 [preauth]\n" +
		// Строку чужой программы с текстом пользователя тоже нельзя принять за sshd.
		"Aug  9 03:00:02 srv sudo[77]:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/echo sshd[1]: Invalid user x from 198.51.100.7 port 1\n" +
		// Настоящие попытки: OpenSSH 9.8+ пишет от имени sshd-session, rsyslog —
		// с меткой времени RFC 3339.
		"Aug  9 03:00:03 srv sshd-session[4242]: Invalid user admin from 203.0.113.9 port 40000\n" +
		"2026-09-11T08:00:04.123456+03:00 srv sshd[5]: Failed password for root from 203.0.113.10 port 22 ssh2\n"
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(lines); err != nil {
		t.Fatal(err)
	}
	f.Close()

	attempts, byIP := CollectSSHFailures(p)

	if byIP["198.51.100.7"] != 0 || byIP["203.0.113.5"] != 0 {
		t.Fatalf("строка без сообщения о входе засчитана попыткой: %v", byIP)
	}
	if byIP["203.0.113.9"] != 1 || byIP["203.0.113.10"] != 1 || attempts != 2 {
		t.Fatalf("настоящие попытки потеряны: attempts=%d %v", attempts, byIP)
	}
}
