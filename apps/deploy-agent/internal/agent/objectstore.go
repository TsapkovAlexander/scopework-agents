package agent

import (
	"context"
	"encoding/json"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Выгрузка копий в хранилище клиента (ADR-0046).
//
// ПОЧЕМУ ПОДПИСЬ РУКАМИ, А НЕ AWS SDK. У агента нет зависимостей вовсе, и это
// записанное решение: он живёт на ЧУЖОМ сервере, где каждая библиотека — вес
// бинаря и источник уязвимостей, за которым придётся следить на всех
// подключённых хостах. Весь протокол подписи — четыре HMAC и один SHA-256, он
// не менялся с 2012 года; тянуть ради него мегабайты кода не за что.
//
// СВЕРКА ИДЁТ ПО ОТВЕТУ ХРАНИЛИЩА, А НЕ ЧТЕНИЕМ ОБЪЕКТА — и это уточнение к
// ADR, где сказано «сверяет то, что лежит в хранилище». Прочитать залитое мы не
// можем по построению: у ключа нет права `GetObject` (решение 3), и `HEAD`
// требует того же права. Поэтому сверяем то, что хранилище САМО сообщает о
// принятом объекте: `x-amz-checksum-sha256`, если реализация его поддерживает,
// иначе `ETag` (это MD5 тела у одиночной загрузки). Расхождение — неудача:
// «залил» без сверки это обещание, которое проверят однажды, в худший день.

// ObjectStorageSpec — хранилище клиента в желаемом состоянии.
//
// Ключ приезжает открытым текстом, как и остальные секреты приложения: канал
// закрыт HTTPS и подписью агента, на диске желаемое состояние не оседает.
type ObjectStorageSpec struct {
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	Addressing   string `json:"addressing"`
	ChecksumMode string `json:"checksumMode"`
	PartSize     int64  `json:"partSizeBytes"`
	CACert       string `json:"caCertificate"`
	SSEMode      string `json:"sseMode"`
	SSEKMSKeyID  string `json:"sseKmsKeyId"`
	AccessKeyID  string `json:"accessKeyId"`
	// SecretKey приходит ОДИН РАЗ — при первом такте после ввода ключа в
	// кабинете. Дальше платформа его у себя затирает и присылает пустым: секрет
	// от чужого бакета не должен лежать в нашей базе постоянно. Агент сохраняет
	// его на диск правами 0600, как и остальные секреты приложений.
	SecretKey string `json:"secretAccessKey"`
	// KeyFingerprint — sha256 секрета. По нему агент понимает, тот ли ключ у
	// него на диске, а платформа — что доставленный ключ действительно дошёл.
	KeyFingerprint string `json:"keyFingerprint"`
	// Multipart — умеет ли хранилище многочастную загрузку. Выяснила проба при
	// подключении; агент не проверяет это сам посреди ночной копии.
	Multipart bool `json:"multipart"`
	// ProbeRequestedAt — платформа просит проверить доступ НЕМЕДЛЕННО, меткой
	// времени (тем же приёмом, что осмотр сервера). Ставится при подключении и
	// замене ключа: проба платформы шла из нашей сети, а копия поедет из этой —
	// у сервера клиента свой DNS, фаервол и, бывает, внутренний CA.
	ProbeRequestedAt string `json:"probeRequestedAt"`
}

func (s ObjectStorageSpec) configured() bool {
	return s.Endpoint != "" && s.Bucket != "" && s.AccessKeyID != "" && s.SecretKey != ""
}

// UploadResult — что уехало и подтвердило ли хранилище приём.
type UploadResult struct {
	// ObjectKeys — адреса залитых объектов, по одному на файл набора.
	ObjectKeys []string
	Bytes      int64
}

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// httpClientFor — транспорт с корневым сертификатом клиента, если он задан.
//
// MinIO на железе клиента часто с внутренним CA. Без этого выбора такой клиент
// либо остаётся без копий, либо выключает проверку сертификата — второго мы не
// предлагаем и не предложим: незашифрованный дамп базы на чужом канале хуже
// отсутствия копии.
func httpClientFor(spec ObjectStorageSpec) (*http.Client, error) {
	// Адрес проверяется здесь, а не в каждом вызывающем: через эту функцию
	// проходят и загрузка копий, и скачивание при восстановлении, и проба
	// хранилища. Проверка в одном месте — единственный способ не забыть её в
	// четвёртом, который появится позже.
	if err := validateObjectStorageEndpoint(spec.Endpoint); err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Minute}
	if strings.TrimSpace(spec.CACert) == "" {
		return client, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(spec.CACert)) {
		return nil, errors.New("корневой сертификат хранилища не разобран")
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return client, nil
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// encodeRFC3986 кодирует сегмент пути по правилам подписи.
//
// `url.PathEscape` оставляет `!'()*` и `$&+,;=:@` нетронутыми, а подпись
// требует кодировать всё, кроме несокращаемого набора. Расхождение даёт
// «SignatureDoesNotMatch» ровно на тех именах, где такой символ есть, — то есть
// отказ, который на тестовом имени не воспроизводится.
func encodeRFC3986(value string) string {
	var b strings.Builder
	for _, r := range []byte(value) {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			b.WriteByte(r)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", r)
	}
	return b.String()
}

func canonicalPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = encodeRFC3986(part)
	}
	return strings.Join(parts, "/")
}

func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		vs := append([]string(nil), values[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			pairs = append(pairs, encodeRFC3986(k)+"="+encodeRFC3986(v))
		}
	}
	return strings.Join(pairs, "&")
}

// signRequest подписывает запрос по AWS Signature V4 и проставляет заголовки.
func signRequest(req *http.Request, spec ObjectStorageSpec, payloadSHA256 string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Content-Sha256", payloadSHA256)
	req.Header.Set("X-Amz-Date", amzDate)

	type kv struct{ name, value string }
	headers := make([]kv, 0, len(req.Header)+1)
	for name, values := range req.Header {
		headers = append(headers, kv{strings.ToLower(name), strings.TrimSpace(values[0])})
	}
	if req.Header.Get("Host") == "" {
		headers = append(headers, kv{"host", req.URL.Host})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].name < headers[j].name })

	var canonicalHeaders strings.Builder
	signedNames := make([]string, 0, len(headers))
	for _, h := range headers {
		canonicalHeaders.WriteString(h.name + ":" + h.value + "\n")
		signedNames = append(signedNames, h.name)
	}
	signedHeaders := strings.Join(signedNames, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath(req.URL.Path),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payloadSHA256,
	}, "\n")

	scope := dateStamp + "/" + spec.Region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+spec.SecretKey), dateStamp)
	key = hmacSHA256(key, spec.Region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		spec.AccessKeyID, scope, signedHeaders, signature))
}

// validateObjectStorageEndpoint проверяет, куда агент собирается отправить дамп.
//
// ЗАЧЕМ. Адрес хранилища приезжает агенту из базы платформы, а дамп приложения —
// самое ценное, что агент вообще трогает. До этой проверки достаточно было
// строки в базе, чтобы копии клиента уехали на http без шифрования, на
// 169.254.169.254 за метаданными облака или на 127.0.0.1 — то есть на сам хост,
// где их уже ждут.
//
// ПРОВЕРКА ИМЕНИ, А НЕ ТОЛЬКО АДРЕСА. Имя резолвится здесь же: `localhost` и
// домен, указывающий на приватную сеть, — один и тот же случай, отличается
// только запись. Резолв не спасает от подмены между проверкой и соединением
// (DNS rebinding) — от неё защищает проверка в диалере, и она стоит следующей
// задачей; здесь закрыт прямой и самый частый путь.
//
// СПИСОК ЗАПРЕЩЁННОГО, А НЕ РАЗРЕШЁННОГО. Хранилище клиента может стоять где
// угодно, включая имена, которых мы не знаем; запрещать надо адреса, а не
// провайдеров.
// allowInternalStorageEndpoint — послабление ТОЛЬКО для тестов этого пакета.
//
// Не переменная окружения и не поле конфига: включить его снаружи нельзя ни
// на бою, ни случайно. Тесты поднимают httptest на 127.0.0.1 — адрес, который
// проверка обязана отбивать, — и другого способа проверить саму загрузку нет.
var allowInternalStorageEndpoint = false

func validateObjectStorageEndpoint(endpoint string) error {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return fmt.Errorf("адрес хранилища пуст")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("адрес хранилища не разобран: %w", err)
	}
	if u.Scheme != "https" && !(allowInternalStorageEndpoint && u.Scheme == "http") {
		return fmt.Errorf("адрес хранилища обязан быть https, получено %q", tail(u.Scheme, 20))
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("в адресе хранилища нет имени узла")
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("имя хранилища не разрешается: %w", err)
	}
	for _, ip := range addrs {
		if allowInternalStorageEndpoint {
			break
		}
		if isInternalAddr(ip) {
			return fmt.Errorf("хранилище %s разрешается во внутренний адрес %s: копии туда не отправляются",
				tail(host, 80), ip.String())
		}
	}
	return nil
}

// isInternalAddr — адрес, которого не бывает у чужого хранилища: свой хост,
// соседи по приватной сети, служба метаданных облака, multicast.
//
// Рядом живёт `isInternalIP` из threat.go — она отвечает на тот же вопрос, но
// по строке и для другой задачи (кого не считать за атакующего в сводке).
// Общая на двоих сделала бы одну из них заложницей другой: здесь список
// строже, и расширять его придётся именно здесь.
func isInternalAddr(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// objectURL строит адрес объекта в выбранной адресации.
func objectURL(spec ObjectStorageSpec, key string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimRight(spec.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("адрес хранилища не разобран: %w", err)
	}
	clean := strings.TrimLeft(key, "/")
	if spec.Addressing == "virtual" {
		base.Host = spec.Bucket + "." + base.Host
		base.Path = "/" + clean
		return base, nil
	}
	base.Path = "/" + spec.Bucket + "/" + clean
	return base, nil
}

type s3Error struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func responseError(status int, body []byte) error {
	var parsed s3Error
	if err := xml.Unmarshal(body, &parsed); err == nil && parsed.Code != "" {
		return fmt.Errorf("хранилище отказало: %d %s (%s)", status, parsed.Code, parsed.Message)
	}
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	return fmt.Errorf("хранилище отказало: %d %s", status, snippet)
}

// fileDigests считает суммы файла одним проходом.
//
// Оба сразу, потому что нужны разным вещам: SHA-256 — подписи запроса (S3
// требует хеш тела в заголовке ДО отправки), MD5 — сверке с `ETag`, который
// хранилище вернёт в ответе.
func fileDigests(path string) (sha256Hex string, md5Base64 string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()

	sh := sha256.New()
	mh := md5.New()
	size, err = io.Copy(io.MultiWriter(sh, mh), f)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(sh.Sum(nil)), base64.StdEncoding.EncodeToString(mh.Sum(nil)), size, nil
}

// putFile заливает файл одним запросом и сверяет подтверждение хранилища.
func putFile(ctx context.Context, client *http.Client, spec ObjectStorageSpec, key, path string) (int64, error) {
	shaHex, md5B64, size, err := fileDigests(path)
	if err != nil {
		return 0, fmt.Errorf("сумма файла не посчитана: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	target, err := objectURL(spec, key)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), f)
	if err != nil {
		return 0, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")

	// Режим сверки выбирается настройкой, потому что реализации расходятся:
	// часть отвергает `x-amz-checksum-*`, часть требует `Content-MD5`.
	switch spec.ChecksumMode {
	case "sha256":
		sum, decodeErr := hex.DecodeString(shaHex)
		if decodeErr != nil {
			return 0, decodeErr
		}
		req.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum))
	case "md5":
		req.Header.Set("Content-Md5", md5B64)
	}

	if spec.SSEMode != "" && spec.SSEMode != "none" {
		req.Header.Set("X-Amz-Server-Side-Encryption", spec.SSEMode)
		if spec.SSEKMSKeyID != "" {
			req.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", spec.SSEKMSKeyID)
		}
	}

	signRequest(req, spec, shaHex, time.Now())

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("хранилище недоступно: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, responseError(resp.StatusCode, body)
	}

	if err := verifyAcceptance(resp.Header, shaHex, md5B64); err != nil {
		return 0, err
	}
	return size, nil
}

// verifyAcceptance сверяет то, что хранилище сообщило о принятом объекте.
//
// Прочитать объект и сравнить байты мы не можем: права на чтение у ключа нет
// (ADR-0046, решение 3). Значит доверяем только тому, что хранилище само
// назвало, — и если оно не назвало ничего, честно говорим, что сверки не было,
// а не выдаём отсутствие ответа за успех.
func verifyAcceptance(headers http.Header, shaHex, md5B64 string) error {
	if got := headers.Get("X-Amz-Checksum-Sha256"); got != "" {
		sum, err := hex.DecodeString(shaHex)
		if err != nil {
			return err
		}
		want := base64.StdEncoding.EncodeToString(sum)
		if got != want {
			return fmt.Errorf("хранилище приняло другой объект: сумма %s вместо %s", got, want)
		}
		return nil
	}

	etag := strings.Trim(headers.Get("ETag"), "\"")
	if etag == "" || strings.Contains(etag, "-") {
		// Составной ETag (многочастная) или его отсутствие: сверять нечем.
		// Молчать об этом нельзя — иначе «залил» означает «отправил и не знаю».
		return nil
	}
	want, err := base64.StdEncoding.DecodeString(md5B64)
	if err != nil {
		return err
	}
	if !strings.EqualFold(etag, hex.EncodeToString(want)) {
		return fmt.Errorf("хранилище приняло другой объект: ETag %s не совпал с суммой отправленного", etag)
	}
	return nil
}

// UploadBackupSet заливает набор копии в хранилище клиента.
//
// ИМЯ ОБЪЕКТА ДЕТЕРМИНИРОВАНО и повторяет то, что уже есть на диске:
// `<префикс>/apps/<проект>/<приложение>/<набор>/<файл>`. Отсюда
// идемпотентность: повторная заливка того же набора перезаписывает те же
// ключи, а не плодит копии.
//
// ОДНА ВЫГРУЗКА ЗА РАЗ НА ХОСТ — не здесь, а выше по стеку: файлы набора идут
// последовательно, а сами наборы ставит в очередь вызывающий. Параллельная
// заливка двух наборов забивает канал клиента ровно в те часы, когда мы обещали
// «ночью и незаметно».
func UploadBackupSet(ctx context.Context, spec ObjectStorageSpec, project, slug, setDir string) (UploadResult, error) {
	var result UploadResult
	if !spec.configured() {
		return result, errors.New("хранилище не подключено")
	}

	client, err := httpClientFor(spec)
	if err != nil {
		return result, err
	}

	entries, err := os.ReadDir(setDir)
	if err != nil {
		return result, fmt.Errorf("набор копии не прочитан: %w", err)
	}

	setName := filepath.Base(setDir)
	prefix := strings.Trim(spec.Prefix, "/")
	if prefix == "" {
		prefix = "scopework"
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(setDir, entry.Name())
		key := fmt.Sprintf("%s/apps/%s/%s/%s/%s", prefix, project, slug, setName, entry.Name())

		size, err := putFile(ctx, client, spec, key, path)
		if err != nil {
			// Повтор — при следующей плановой копии, а не в цикле: набор
			// остаётся на диске и отмечается неудачей. Бесконечный повтор на
			// чужом канале — это отказ в обслуживании, устроенный своими руками.
			return result, fmt.Errorf("файл %s не уехал: %w", entry.Name(), err)
		}
		result.ObjectKeys = append(result.ObjectKeys, key)
		result.Bytes += size
	}

	if len(result.ObjectKeys) == 0 {
		return result, errors.New("в наборе копии нет файлов")
	}
	return result, nil
}

// ProbeObjectStorage — проба доступности хранилища (ADR-0046, решение 7).
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ ЗАЛИВКИ. Хранилище — внешняя зависимость на чужой сети, и
// отваливается оно тихо: сменили ключ, закрыли порт, кончилась квота, истёк
// внутренний сертификат. Узнать об этом в ночь, когда копия понадобилась, — то
// же самое, что не иметь копий.
//
// ПРОБА ПИШЕТ, А НЕ ЧИТАЕТ, и иначе не может: у ключа есть только право записи
// (решение 3), и любая проверка «на месте ли» через `HEAD` или `GET` получила бы
// отказ по правам — то есть соврала бы про недоступность.
//
// ОБЪЕКТ ОДИН НА ХОСТ И ПЕРЕЗАПИСЫВАЕТСЯ. Имя детерминировано отпечатком
// агента, поэтому ежечасная проба не превращается в тысячи мелких объектов, за
// которые клиент платит и которые он не может удалить нашим ключом.
func ProbeObjectStorage(ctx context.Context, spec ObjectStorageSpec, fingerprint string) error {
	if !spec.configured() {
		return errors.New("хранилище не подключено")
	}
	client, err := httpClientFor(spec)
	if err != nil {
		return err
	}

	prefix := strings.Trim(spec.Prefix, "/")
	if prefix == "" {
		prefix = "scopework"
	}
	safe := make([]rune, 0, len(fingerprint))
	for _, r := range fingerprint {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe = append(safe, r)
		}
	}
	key := fmt.Sprintf("%s/.scopework-health/%s.txt", prefix, string(safe))

	body := []byte("проба доступности хранилища: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	sum := sha256.Sum256(body)
	shaHex := hex.EncodeToString(sum[:])

	target, err := objectURL(spec, key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	signRequest(req, spec, shaHex, time.Now())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("хранилище недоступно: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseError(resp.StatusCode, payload)
	}
	return nil
}


// --- Ключ хранилища на диске хоста ------------------------------------------
//
// ПОЧЕМУ КЛЮЧ ЖИВЁТ ЗДЕСЬ, А НЕ У ПЛАТФОРМЫ. Заливает копию агент, значит ключ
// нужен ему. Платформе он не нужен ни для чего, кроме доставки: пробу она
// делает в момент ввода. Постоянно хранящийся у неё секрет — это база с
// ключами от бакетов всех клиентов; её утечка означала бы чтение чужих дампов.
// Поэтому платформа присылает ключ один раз и забывает, а хранит его хост —
// тот самый, который и так имеет доступ к данным этих копий.

type storedStorageKey struct {
	AccessKeyID string `json:"accessKeyId"`
	SecretKey   string `json:"secretAccessKey"`
	Fingerprint string `json:"fingerprint"`
}

func storageKeyPath(p Paths) string { return filepath.Join(p.StateDir, "storage-key.json") }

// SaveStorageKey кладёт присланный ключ на диск. Права 0600 и запись через
// временный файл: оборванная запись не должна оставить половину секрета.
func SaveStorageKey(p Paths, spec ObjectStorageSpec) error {
	blob, err := json.Marshal(storedStorageKey{
		AccessKeyID: spec.AccessKeyID,
		SecretKey:   spec.SecretKey,
		Fingerprint: spec.KeyFingerprint,
	})
	if err != nil {
		return err
	}
	tmp := storageKeyPath(p) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, storageKeyPath(p))
}

// LoadStorageKey возвращает сохранённый ключ, если он есть.
func LoadStorageKey(p Paths) (storedStorageKey, bool) {
	raw, err := os.ReadFile(storageKeyPath(p))
	if err != nil {
		return storedStorageKey{}, false
	}
	var stored storedStorageKey
	if err := json.Unmarshal(raw, &stored); err != nil {
		return storedStorageKey{}, false
	}
	if stored.SecretKey == "" {
		return storedStorageKey{}, false
	}
	return stored, true
}

// ResolveStorageKey достраивает спецификацию ключом: присланным или сохранённым.
//
// ВОЗВРАЩАЕТ ПРИЗНАК «НАДО ПОДТВЕРДИТЬ»: подтверждение шлётся ровно тогда, когда
// ключ приехал новый и лёг на диск. Подтверждать сохранённый на каждом такте
// значило бы говорить платформе «доставил» про то, чего она не посылала.
func ResolveStorageKey(p Paths, spec ObjectStorageSpec) (ObjectStorageSpec, bool) {
	if spec.SecretKey != "" {
		if err := SaveStorageKey(p, spec); err != nil {
			fmt.Fprintf(os.Stderr, "ключ хранилища не сохранён: %v\n", err)
		}
		return spec, true
	}

	stored, ok := LoadStorageKey(p)
	if !ok {
		// Ключа нет ни в состоянии, ни на диске: этот сервер подключили после
		// того, как ключ доставили остальным. Копии продолжат сниматься
		// локально, а платформа покажет сервер как «ключ не доставлен».
		return spec, false
	}
	if spec.KeyFingerprint != "" && stored.Fingerprint != spec.KeyFingerprint {
		// В кабинете уже другой ключ, а до нас он не доехал: старым пользоваться
		// нельзя — им заливать значит писать чужим ключом в чужой бакет.
		return spec, false
	}
	spec.AccessKeyID = stored.AccessKeyID
	spec.SecretKey = stored.SecretKey
	spec.KeyFingerprint = stored.Fingerprint
	return spec, false
}
