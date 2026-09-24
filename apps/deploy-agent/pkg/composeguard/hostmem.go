package composeguard

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Память хоста в tmpfs и /dev/shm: пределы и их разбор.
//
// Одна реализация на троих: политика compose (Check) у агента и у подписанта и
// прокси сокета Docker агента (internal/agent/dockerproxy.go). Стек, прошедший
// проверку текста, обязан пройти и прокси, иначе проверка текста врёт — а своя
// копия правила разошлась бы с прокси на первой же правке предела или разбора
// суффикса. Совпадение вердиктов держит TestComposeGuardPamyatSoglasovanaSProxy
// в internal/agent: там видны обе стороны.

// MaxTmpfsBytes — предел одного tmpfs.
//
// tmpfs лежит в памяти хоста, и без `size` ядро даёт ему половину всей памяти
// сервера: один контейнер, пишущий в /tmp, выдавливает соседние приложения
// клиента в OOM. 512 МиБ — с запасом для того, для чего tmpfs берут на деле
// (/run, /tmp, кеш nginx; собственный раннер платформы живёт на 256 МиБ), и
// при этом четверть памяти самого малого сервера в 2 ГиБ, а не половина.
const MaxTmpfsBytes = 512 << 20

// MaxShmBytes — предел /dev/shm контейнера.
//
// /dev/shm — это tmpfs в памяти хоста, и ShmSize задаёт ему размер числом
// байт, мимо проверки опций tmpfs: без предела здесь тот же канал «занять
// память хоста», что закрыт для Tmpfs и Mounts. Предел выше, чем у tmpfs, по
// одной причине: headless Chrome держит в /dev/shm буферы отрисовки и на
// штатных 64 МиБ падает, а шаблонам с ним нужно 1–2 ГиБ. Больше не просит ни
// один законный случай; на малом сервере и 2 ГиБ — много, поэтому второй рубеж
// — лимит памяти контейнера, в который страницы /dev/shm тоже засчитываются.
const MaxShmBytes = 2 << 30

// CheckShmSize — размер /dev/shm в байтах (HostConfig.ShmSize).
//
// 0 здесь, в отличие от tmpfs, не безлимит: демон заменяет его штатным
// размером (64 МиБ или --default-shm-size хоста — moby, daemon_unix.go,
// adaptContainerSettings). Отрицательный демон отвергает сам; отвергаем и мы,
// чтобы решение не зависело от проверки за нами.
func CheckShmSize(n int64) error {
	if n < 0 {
		return fmt.Errorf("%d: отрицательный размер /dev/shm", n)
	}
	if n > MaxShmBytes {
		return fmt.Errorf("%d байт больше предела прокси %d МиБ на /dev/shm (память хоста)",
			n, MaxShmBytes>>20)
	}
	return nil
}

// CheckTmpfsOptions — опции tmpfs строкой: предел обязателен и не больше
// MaxTmpfsBytes.
//
// Проверяется КАЖДЫЙ size, а не первый: ядро применяет последний, и
// `size=64m,size=0` выглядел бы пределом, оставаясь безлимитом.
//
// Флаги bind, rbind, move и remount запрещены: демон переводит их в флаги
// mount(2), а при MS_BIND (и MS_MOVE, MS_REMOUNT) ядро игнорирует тип
// файловой системы и data. «tmpfs» с bind — это привязка каталога хоста
// (у тома local — device, вплоть до `/`) на запись в контейнер, и предел size
// к ней уже не относится. Сравнение без учёта регистра: ядро различает
// регистр, но гадать, какое написание демон примет, дороже, чем отказать.
// Функция общая для HostConfig.Tmpfs, Mounts с типом tmpfs и тома local
// с type=tmpfs — все три пути сходятся в одну строку опций.
func CheckTmpfsOptions(options string) error {
	sized := false
	for _, opt := range strings.Split(options, ",") {
		opt = strings.TrimSpace(opt)
		key, value, _ := strings.Cut(opt, "=")
		switch strings.ToLower(key) {
		case "bind", "rbind", "move", "remount":
			return fmt.Errorf("%s: с этим флагом ядро игнорирует тип tmpfs и монтирует каталог хоста", tail(opt, 40))
		case "size":
			n, err := parseTmpfsSize(value)
			if err != nil {
				return fmt.Errorf("size=%s: %s", tail(value, 40), err.Error())
			}
			if n > MaxTmpfsBytes {
				return fmt.Errorf("size=%s больше предела прокси %d МиБ на одно монтирование tmpfs",
					tail(value, 40), MaxTmpfsBytes>>20)
			}
			sized = true
		case "nr_blocks":
			// Второй способ задать размер, в страницах памяти; 0 снимает
			// предел. Размер страницы у хостов разный, поэтому не считаем, а
			// просим задавать размер одним способом.
			return errors.New("nr_blocks: размер tmpfs задаётся только через size")
		}
	}
	if !sized {
		return fmt.Errorf("не задан size: tmpfs без предела занимает до половины памяти хоста (предел прокси %d МиБ)",
			MaxTmpfsBytes>>20)
	}
	return nil
}

// parseTmpfsSize — размер tmpfs в байтах: целое число с необязательным
// суффиксом k, m, g, t (как у ядра).
//
// Проценты — это доля памяти хоста, а не предел: `size=90%` пропустил бы ровно
// то, от чего проверка стоит. Шестнадцатеричную и прочую запись не принимаем:
// разбор, расходящийся с ядерным, — это предел, который проверен не тот.
func parseTmpfsSize(value string) (int64, error) {
	if strings.HasSuffix(value, "%") {
		return 0, errors.New("доля памяти хоста, а не предел — задайте размер в байтах, k, m или g")
	}
	digits := value
	multiplier := int64(1)
	if n := len(value); n > 0 {
		switch value[n-1] {
		case 'k', 'K':
			multiplier = 1 << 10
		case 'm', 'M':
			multiplier = 1 << 20
		case 'g', 'G':
			multiplier = 1 << 30
		case 't', 'T':
			multiplier = 1 << 40
		}
		if multiplier != 1 {
			digits = value[:n-1]
		}
	}
	if digits == "" || strings.TrimLeft(digits, "0123456789") != "" {
		return 0, errors.New("размер не разобран — ожидается число с суффиксом k, m или g")
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n > (1<<62)/multiplier {
		// Число, не влезающее в int64, заведомо больше предела.
		return 1 << 62, nil
	}
	if n == 0 {
		return 0, errors.New("0 снимает предел tmpfs")
	}
	return n * multiplier, nil
}
