package agent

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Проверки выгрузки копий в хранилище клиента (ADR-0046).
//
// ЧТО ЗДЕСЬ, А ЧТО НА ЖИВОМ MinIO. Здесь — то, что можно проверить без сети:
// форма подписи, детерминированные имена объектов, сверка подтверждения,
// поведение при отказе. Верна ли подпись ПО СУЩЕСТВУ, решает только сервер:
// это `TestUploadToLiveStorage` ниже, он идёт из `scripts/check-s3-probe.sh` на
// поднятом MinIO. Тест, сверяющий подпись с самим собой, зеленел бы и при
// полностью неверной реализации.

func specFor(endpoint string) ObjectStorageSpec {
	return ObjectStorageSpec{
		Endpoint:     endpoint,
		Region:       "ru-central1",
		Bucket:       "backups",
		Prefix:       "scopework",
		Addressing:   "path",
		ChecksumMode: "md5",
		AccessKeyID:  "agent-key",
		SecretKey:    "agent-secret",
	}
}

func writeSet(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "20260910-030000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func md5Hex(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

func TestUploadBackupSetNamesObjectsDeterministically(t *testing.T) {
	allowLocalStorage(t)
	var gotPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		w.Header().Set("ETag", "\""+md5Hex(string(body))+"\"")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := writeSet(t, map[string]string{"db.sql.gz": "дамп", "data.tar.gz": "том"})
	result, err := UploadBackupSet(context.Background(), specFor(server.URL), "shop", "api", dir)
	if err != nil {
		t.Fatalf("выгрузка не прошла: %v", err)
	}
	if len(result.ObjectKeys) != 2 {
		t.Fatalf("залито объектов %d, ожидалось 2", len(result.ObjectKeys))
	}
	for _, path := range gotPaths {
		// Имя повторяет то, что лежит на диске: повторная заливка того же
		// набора перезаписывает те же ключи, а не плодит копии.
		if !strings.HasPrefix(path, "/backups/scopework/apps/shop/api/20260910-030000/") {
			t.Fatalf("неожиданный адрес объекта: %s", path)
		}
	}
}

func TestUploadBackupSetSignsEveryRequest(t *testing.T) {
	allowLocalStorage(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=agent-key/") {
			t.Errorf("запрос без подписи: %q", auth)
		}
		if !strings.Contains(auth, "/ru-central1/s3/aws4_request") {
			t.Errorf("подпись не привязана к региону и сервису: %q", auth)
		}
		if r.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Error("нет суммы тела: подпись без неё принимается не всеми реализациями")
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		w.Header().Set("ETag", "\""+md5Hex(string(body))+"\"")
	}))
	defer server.Close()

	dir := writeSet(t, map[string]string{"db.sql.gz": "дамп"})
	if _, err := UploadBackupSet(context.Background(), specFor(server.URL), "shop", "api", dir); err != nil {
		t.Fatalf("выгрузка не прошла: %v", err)
	}
}

func TestUploadRejectsWrongAcceptance(t *testing.T) {
	allowLocalStorage(t)
	// Хранилище приняло ДРУГОЙ объект: «залил» без сверки это обещание, которое
	// проверят однажды, в худший день.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"00000000000000000000000000000000\"")
	}))
	defer server.Close()

	dir := writeSet(t, map[string]string{"db.sql.gz": "дамп"})
	_, err := UploadBackupSet(context.Background(), specFor(server.URL), "shop", "api", dir)
	if err == nil || !strings.Contains(err.Error(), "другой объект") {
		t.Fatalf("расхождение сумм обязано быть неудачей, получено: %v", err)
	}
}

func TestUploadStopsOnDeniedAndDoesNotRetryForever(t *testing.T) {
	allowLocalStorage(t)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>нет прав</Message></Error>`)
	}))
	defer server.Close()

	dir := writeSet(t, map[string]string{"db.sql.gz": "дамп", "data.tar.gz": "том"})
	_, err := UploadBackupSet(context.Background(), specFor(server.URL), "shop", "api", dir)
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("отказ хранилища обязан дойти до вызывающего: %v", err)
	}
	if attempts != 1 {
		// Повтор — при следующей плановой копии. Бесконечный повтор на чужом
		// канале это отказ в обслуживании, устроенный своими руками.
		t.Fatalf("попыток %d, ожидалась одна: повтор в цикле запрещён", attempts)
	}
}

func TestUploadRefusesWithoutStorage(t *testing.T) {
	dir := writeSet(t, map[string]string{"db.sql.gz": "дамп"})
	_, err := UploadBackupSet(context.Background(), ObjectStorageSpec{}, "shop", "api", dir)
	if err == nil || !strings.Contains(err.Error(), "не подключено") {
		t.Fatalf("без настроек выгрузка обязана отказать внятно: %v", err)
	}
}

func TestSignatureIsDeterministicAndBoundToTime(t *testing.T) {
	spec := specFor("https://s3.example.com")
	at := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)

	sign := func(when time.Time) string {
		req, err := http.NewRequest(http.MethodPut, "https://s3.example.com/backups/scopework/x.bin", nil)
		if err != nil {
			t.Fatal(err)
		}
		signRequest(req, spec, emptyPayloadSHA256, when)
		return req.Header.Get("Authorization")
	}

	if sign(at) != sign(at) {
		t.Fatal("подпись не детерминирована")
	}
	if sign(at) == sign(at.Add(24*time.Hour)) {
		t.Fatal("подпись не привязана к дате: утёкшая годилась бы и завтра")
	}
}

func TestObjectURLAddressing(t *testing.T) {
	spec := specFor("https://storage.yandexcloud.net")
	path, err := objectURL(spec, "scopework/apps/x.tar")
	if err != nil {
		t.Fatal(err)
	}
	if path.String() != "https://storage.yandexcloud.net/backups/scopework/apps/x.tar" {
		t.Fatalf("path-style собран неверно: %s", path)
	}

	spec.Addressing = "virtual"
	virtual, err := objectURL(spec, "scopework/apps/x.tar")
	if err != nil {
		t.Fatal(err)
	}
	if virtual.String() != "https://backups.storage.yandexcloud.net/scopework/apps/x.tar" {
		t.Fatalf("virtual-hosted собран неверно: %s", virtual)
	}
}

// TestUploadToLiveStorage — единственная проверка подписи по существу.
//
// Идёт только когда поднято настоящее хранилище: `scripts/check-s3-probe.sh`
// поднимает MinIO и передаёт его адрес. Без него тест пропускается — и это не
// молчаливый зелёный, потому что сам скрипт без Docker падает, а не
// пропускается.
func TestUploadToLiveStorage(t *testing.T) {
	endpoint := os.Getenv("S3_PROBE_ENDPOINT")
	if endpoint == "" {
		t.Skip("нет S3_PROBE_ENDPOINT: живое хранилище поднимает check-s3-probe.sh")
	}

	// Послабление на внутренний адрес — то же, что у соседнего теста.
	//
	// С 18.09.2026 (задача С1.10) агент отбивает хранилище на http и на
	// внутреннем адресе: дамп базы клиента — самое ценное, что он трогает.
	// MinIO из check-s3-probe.sh стоит ровно там — http://127.0.0.1, — и без
	// этой строки единственная проверка подписи по существу перестала
	// выполняться вовсе. Снаружи послабление не включается ничем: это
	// переменная пакета, а не флаг и не переменная окружения.
	allowInternalStorageEndpoint = true
	t.Cleanup(func() { allowInternalStorageEndpoint = false })

	spec := specFor(endpoint)
	spec.AccessKeyID = "agent-key"
	spec.SecretKey = "agent-key-secret"
	spec.ChecksumMode = "none"

	dir := writeSet(t, map[string]string{
		"db.sql.gz":   "дамп базы клиента",
		"data.tar.gz": "архив тома",
	})

	result, err := UploadBackupSet(context.Background(), spec, "shop", "api", dir)
	if err != nil {
		t.Fatalf("живое хранилище не приняло набор: %v", err)
	}
	if len(result.ObjectKeys) != 2 || result.Bytes == 0 {
		t.Fatalf("залито %d объектов, %d байт", len(result.ObjectKeys), result.Bytes)
	}
}

// ─── С1.10: адрес хранилища копий ─────────────────────────────────────────
//
// Адрес приезжает агенту из базы платформы. Дамп приложения клиента — самое
// ценное, что агент вообще трогает, и до этих проверок он отправил бы его
// куда угодно: на http без шифрования, на 169.254.169.254 за метаданными
// облака, на 127.0.0.1 или в приватную сеть рядом с собой.

// Загрузка и скачивание проверяются на httptest, то есть на 127.0.0.1 — адресе,
// который проверка адреса обязана отбивать. Послабление включается на время
// этих тестов и снимается сразу: снаружи его не включить ничем.
func allowLocalStorage(t *testing.T) {
	t.Helper()
	allowInternalStorageEndpoint = true
	t.Cleanup(func() { allowInternalStorageEndpoint = false })
}

func TestObjectStorageRejectsPlainHttp(t *testing.T) {
	err := validateObjectStorageEndpoint("http://storage.example.com")
	if err == nil {
		t.Fatal("адрес без TLS принят: дамп уехал бы открытым текстом")
	}
}

func TestObjectStorageRejectsLocalAndPrivateTargets(t *testing.T) {
	for _, endpoint := range []string{
		"https://127.0.0.1:9000",
		"https://localhost:9000",
		"https://169.254.169.254",
		"https://10.1.2.3",
		"https://192.168.0.10",
		"https://172.16.5.4",
		"https://[::1]:9000",
	} {
		if err := validateObjectStorageEndpoint(endpoint); err == nil {
			t.Fatalf("принят внутренний адрес: %s", endpoint)
		}
	}
}

func TestObjectStorageAllowsOrdinaryEndpoint(t *testing.T) {
	// Публичное имя проверку проходит: запрет внутреннего не должен мешать
	// обычному хранилищу.
	if err := validateObjectStorageEndpoint("https://s3.storage.selcloud.ru"); err != nil {
		t.Fatalf("обычный адрес отклонён: %v", err)
	}
}

func TestObjectStorageRejectsGarbage(t *testing.T) {
	for _, endpoint := range []string{"", "s3.example.com", "https://", "ftp://s3.example.com"} {
		if err := validateObjectStorageEndpoint(endpoint); err == nil {
			t.Fatalf("принят неразобранный адрес: %q", endpoint)
		}
	}
}
