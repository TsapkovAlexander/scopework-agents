package agent

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"testing/quick"
	"time"
)

// Разбор файла политики хоста (ADR-0095, п. 1). Тот же текст читают агент
// мониторинга и install.sh, поэтому семантика — общая фикстура: разойдись
// разборы в мелочи (хвостовой комментарий, CRLF, байты против символов), и один
// агент исполнит файл, а другой закроет всё по той же строке.

type hostPolicyFixture struct {
	CommandKinds []string `json:"commandKinds"`
	MaxBytes     int      `json:"maxBytes"`
	Cases        []struct {
		Name   string  `json:"name"`
		Text   *string `json:"text"`
		Expect struct {
			State               string   `json:"state"`
			Mode                string   `json:"mode"`
			Commands            []string `json:"commands"`
			DeployAgentUpdates  string   `json:"deployAgentUpdates"`
			MonitorAgentUpdates string   `json:"monitorAgentUpdates"`
			ContainerLogs       string   `json:"containerLogs"`
		} `json:"expect"`
	} `json:"cases"`
	UpdateCases []struct {
		Name            string  `json:"name"`
		Text            *string `json:"text"`
		ReleaseKeys     bool    `json:"releaseKeys"`
		DeployEffective string  `json:"deployEffective"`
	} `json:"updateCases"`
	PermitCases []struct {
		Name      string `json:"name"`
		Rule      string `json:"rule"`
		Current   string `json:"current"`
		Target    string `json:"target"`
		Permitted bool   `json:"permitted"`
	} `json:"permitCases"`
}

func loadHostPolicyFixture(t *testing.T) hostPolicyFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..",
		"packages", "deploy-core", "fixtures", "host-policy.json"))
	if err != nil {
		t.Fatalf("фикстура политики не читается: %v", err)
	}
	var fx hostPolicyFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("фикстура политики не разбирается: %v", err)
	}
	// «Случаев нет» — это не «все прошли»: пустая фикстура сделала бы тест
	// зелёным, ничего не проверив.
	if len(fx.Cases) < 50 {
		t.Fatalf("в фикстуре %d случаев — проверка не проведена", len(fx.Cases))
	}
	return fx
}

// withPolicyPath направляет чтение политики во временный каталог.
func withPolicyPath(t *testing.T, path string) {
	t.Helper()
	prev := PolicyPath
	PolicyPath = path
	t.Cleanup(func() { PolicyPath = prev })
}

func TestPolicyCommandKindsMatchFixture(t *testing.T) {
	fx := loadHostPolicyFixture(t)
	if !reflect.DeepEqual(CommandKinds, fx.CommandKinds) {
		t.Fatalf("закрытый список видов агента %v, в фикстуре %v", CommandKinds, fx.CommandKinds)
	}
	if PolicyMaxBytes != fx.MaxBytes {
		t.Fatalf("предел файла агента %d, в фикстуре %d", PolicyMaxBytes, fx.MaxBytes)
	}
}

func TestPolicyParseFixture(t *testing.T) {
	fx := loadHostPolicyFixture(t)
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "agent-policy.conf")
			if tc.Text != nil {
				if err := os.WriteFile(path, []byte(*tc.Text), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			// Разбор текста и чтение файла обязаны давать одно и то же: файл —
			// это тот же текст плюс проверка владельца.
			fromFile := LoadLocalPolicyFrom(path)
			checks := []LocalPolicy{fromFile}
			if tc.Text != nil {
				checks = append(checks, ParsePolicy([]byte(*tc.Text)))
			}
			for _, got := range checks {
				want := tc.Expect
				if got.State != want.State {
					t.Fatalf("состояние %q, ожидалось %q (ошибка: %s)", got.State, want.State, got.Err)
				}
				if want.State == PolicyAbsent {
					continue
				}
				if got.Mode != want.Mode || got.ContainerLogs != want.ContainerLogs ||
					got.DeployAgentUpdates.String() != want.DeployAgentUpdates ||
					got.MonitorAgentUpdates.String() != want.MonitorAgentUpdates {
					t.Fatalf("значения %+v, ожидалось %+v", got, want)
				}
				if got.Commands == nil || !reflect.DeepEqual(got.Commands, want.Commands) {
					t.Fatalf("commands %#v, ожидалось %#v", got.Commands, want.Commands)
				}
				if (got.State == PolicyInvalid) != (got.Err != "") {
					t.Fatalf("ошибка %q при состоянии %q", got.Err, got.State)
				}
			}
			if tc.Text != nil && fromFile.Sha256 != sha256Hex(*tc.Text) {
				t.Fatalf("sha256 файла %q, ожидался хеш его байтов", fromFile.Sha256)
			}
		})
	}
}

// fakeInfo — ответ подменного stat: владелец и права без root на машине прогона.
type fakeInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "fake" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func withPolicyStat(t *testing.T, file, dir fakeInfo) {
	t.Helper()
	prevL, prevS := policyLstat, policyStat
	policyLstat = func(string) (os.FileInfo, error) { return file, nil }
	policyStat = func(string) (os.FileInfo, error) { return dir, nil }
	t.Cleanup(func() { policyLstat, policyStat = prevL, prevS })
}

func TestPolicyProtection(t *testing.T) {
	rootFile := fakeInfo{mode: 0o644, uid: 0}
	rootDir := fakeInfo{mode: os.ModeDir | 0o755, uid: 0}
	cases := []struct {
		name      string
		file, dir fakeInfo
		want      bool
	}{
		{"root:root 0644 в каталоге root 0755 — защищён", rootFile, rootDir, true},
		{"владелец файла не root", fakeInfo{mode: 0o644, uid: 1000}, rootDir, false},
		{"файл доступен на запись группе", fakeInfo{mode: 0o664, uid: 0}, rootDir, false},
		{"файл доступен на запись прочим", fakeInfo{mode: 0o646, uid: 0}, rootDir, false},
		{"файл — символическая ссылка", fakeInfo{mode: os.ModeSymlink | 0o777, uid: 0}, rootDir, false},
		{"каталог не root", rootFile, fakeInfo{mode: os.ModeDir | 0o755, uid: 1000}, false},
		{"каталог доступен на запись группе", rootFile, fakeInfo{mode: os.ModeDir | 0o775, uid: 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent-policy.conf")
			if err := os.WriteFile(path, []byte("version=1\nmode=observe\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			withPolicyStat(t, tc.file, tc.dir)
			got := LoadLocalPolicyFrom(path)
			if got.Protected != tc.want {
				t.Fatalf("protected=%v, ожидалось %v (%s)", got.Protected, tc.want, got.Unprotected)
			}
			if !tc.want && got.Unprotected == "" {
				t.Fatal("незащищённый файл без причины — владелец не узнает, что чинить")
			}
			// Незащищённый файл всё равно исполняется: строже — безопасно.
			if got.State != PolicyValid || got.Mode != PolicyModeObserve {
				t.Fatalf("незащищённая политика не исполняется: %+v", got)
			}
		})
	}
}

func TestPolicyUnreadableClosesEverything(t *testing.T) {
	t.Run("каталог на месте файла", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent-policy.conf")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		assertClosed(t, LoadLocalPolicyFrom(path))
	})
	t.Run("нет прав на чтение", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root читает файл с любыми правами — проверять нечего")
		}
		path := filepath.Join(t.TempDir(), "agent-policy.conf")
		if err := os.WriteFile(path, []byte("version=1\nmode=deploy\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		got := LoadLocalPolicyFrom(path)
		assertClosed(t, got)
		if got.Sha256 != "" {
			t.Fatalf("у нечитаемого файла sha256 %q", got.Sha256)
		}
	})
	t.Run("файла нет — прежнее поведение", func(t *testing.T) {
		got := LoadLocalPolicyFrom(filepath.Join(t.TempDir(), "nope.conf"))
		if got.State != PolicyAbsent {
			t.Fatalf("нет файла, а состояние %q", got.State)
		}
	})
}

func assertClosed(t *testing.T, p LocalPolicy) {
	t.Helper()
	if p.State != PolicyInvalid || p.Err == "" || p.Mode != PolicyModeObserve || len(p.Commands) != 0 ||
		p.DeployAgentUpdates.String() != "manual" || p.MonitorAgentUpdates.String() != "manual" ||
		p.ContainerLogs != "deny" {
		t.Fatalf("негодный файл не закрыл всё: %+v", p)
	}
}

func TestPolicyErrorFitsReport(t *testing.T) {
	long := "version=1\n" + strings.Repeat("я", 300) + "=1\n"
	got := ParsePolicy([]byte(long))
	if got.State != PolicyInvalid {
		t.Fatalf("незнакомый ключ принят: %+v", got)
	}
	if utf16Len(got.Err) > 500 {
		t.Fatalf("текст ошибки %d знаков — платформа отвергнет доклад", utf16Len(got.Err))
	}
}

// Доклад такта: ровно те поля, которые принимает разбор платформы
// (apps/web/src/lib/deploy/hostPolicy.ts считает лишний ключ мусором).
func TestPolicyReportShape(t *testing.T) {
	keys := func(t *testing.T, v any) []string {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	absent := LocalPolicy{State: PolicyAbsent}.Report(false)
	if raw, _ := json.Marshal(absent); string(raw) != `{"present":false}` {
		t.Fatalf("доклад без файла %s", raw)
	}

	valid := ParsePolicy([]byte("version=1\ndeploy_agent_updates=auto\n"))
	report := valid.Report(false)
	want := []string{"commands", "containerLogs", "deployAgentUpdates", "deployAgentUpdatesEffective",
		"mode", "monitorAgentUpdates", "present", "protected", "sha256"}
	if got := keys(t, report); !reflect.DeepEqual(got, want) {
		t.Fatalf("ключи доклада %v, ожидались %v", got, want)
	}
	if raw, _ := json.Marshal(report); !strings.Contains(string(raw), `"commands":[]`) ||
		!strings.Contains(string(raw), `"deployAgentUpdates":"auto"`) ||
		!strings.Contains(string(raw), `"deployAgentUpdatesEffective":"manual"`) {
		t.Fatalf("observe+auto без ключа выпуска доложено не как manual или commands не массив: %s", raw)
	}
	if withKey := valid.Report(true); withKey.DeployAgentUpdatesEffective != "auto" {
		t.Fatalf("с ключом выпуска действующее %q", withKey.DeployAgentUpdatesEffective)
	}

	// error — только у негодного файла, и только с закрытыми значениями.
	invalid := ParsePolicy([]byte("version=2\n")).Report(true)
	wantInvalid := append(append([]string{}, want...), "error")
	sort.Strings(wantInvalid)
	if got := keys(t, invalid); !reflect.DeepEqual(got, wantInvalid) {
		t.Fatalf("ключи доклада негодного файла %v, ожидались %v", got, wantInvalid)
	}
}

// Файла нет — всё как в 2.1.0: ни одна строка поведения не меняется от того,
// что выкатили версию с политикой.
func TestDecideAbsentPolicyKeepsOldBehaviour(t *testing.T) {
	hb := HeartbeatResponse{
		InventoryRequestedAt: "2026-09-23T10:00:00Z",
		Task:                 &HostTask{ID: "t1", Kind: "backup"},
	}
	state := DesiredState{Apps: []DesiredApp{}, ObjectStorage: &ObjectStorageSpec{}}
	plan := Decide(LocalPolicy{State: PolicyAbsent}, hb, state, false)
	if !plan.Apply || !plan.Recover || !plan.Storage || !plan.Inventory ||
		plan.Task == nil || plan.Refused != nil || plan.BaselineDrift || plan.Updates.Kind != "auto" {
		t.Fatalf("без файла поведение изменилось: %+v", plan)
	}
	// Состояния в ответе нет — применять нечего и без политики.
	if Decide(LocalPolicy{State: PolicyAbsent}, hb, DesiredState{}, false).Apply {
		t.Fatal("ответ без apps применяется")
	}
}

func TestDecideDeployFollowsCommands(t *testing.T) {
	policy := ParsePolicy([]byte("version=1\nmode=deploy\ncommands=inventory,restore\n"))
	hb := HeartbeatResponse{
		InventoryRequestedAt: "x",
		Task:                 &HostTask{ID: "t1", Kind: "backup"},
	}
	plan := Decide(policy, hb, DesiredState{
		Apps: []DesiredApp{{Slug: "shop"}}, ObjectStorage: &ObjectStorageSpec{},
	}, false)
	if plan.Apply || plan.Recover {
		t.Fatalf("без apply в списке состояние применяется: %+v", plan)
	}
	if !plan.BaselineDrift {
		t.Fatal("без применения дрейф сверяется с желаемым — «в пути» быть нечему")
	}
	if plan.Task != nil || plan.Refused == nil || !strings.Contains(plan.RefuseReason, "backup") {
		t.Fatalf("backup вне списка не отклонён: %+v", plan)
	}
	if !plan.Inventory || !plan.Storage {
		t.Fatalf("осмотр из списка или хранилище в deploy запрещены: %+v", plan)
	}

	hb.Task = &HostTask{ID: "t2", Kind: "restore"}
	if plan := Decide(policy, hb, DesiredState{}, false); plan.Task == nil || plan.Refused != nil {
		t.Fatalf("restore из списка не исполняется: %+v", plan)
	}

	all := ParsePolicy([]byte("version=1\nmode=deploy\n"))
	if plan := Decide(all, hb, DesiredState{Apps: []DesiredApp{}}, false); !plan.Apply || !plan.Recover || plan.Task == nil {
		t.Fatalf("mode=deploy без списка — все виды, а план %+v", plan)
	}

	for _, kind := range []string{"shell", "inventory", "apply"} {
		hb.Task = &HostTask{ID: "t3", Kind: kind}
		if plan := Decide(all, hb, DesiredState{}, false); plan.Task != nil || plan.Refused == nil {
			t.Fatalf("задание вида %q при политике исполняется: %+v", kind, plan)
		}
	}
}

// observeInput — произвольный ответ платформы и произвольная политика
// наблюдения (годная observe либо негодный файл, который закрывает всё).
type observeInput struct {
	Policy LocalPolicy
	HB     HeartbeatResponse
	State  DesiredState
	Keys   bool
}

func (observeInput) Generate(r *rand.Rand, _ int) reflect.Value {
	pick := func(options ...string) string { return options[r.Intn(len(options))] }
	kinds := append(append([]string{}, CommandKinds...), "shell", "", "APPLY")

	var text strings.Builder
	text.WriteString("version=1\nmode=observe\n")
	if r.Intn(2) == 0 {
		var chosen []string
		for _, k := range CommandKinds {
			if r.Intn(2) == 0 {
				chosen = append(chosen, k)
			}
		}
		text.WriteString("commands=" + strings.Join(chosen, ",") + "\n")
	}
	text.WriteString("deploy_agent_updates=" + pick("manual", "no_major", "auto", "pinned 2.3.0", "pinned 9.9.9") + "\n")
	policy := ParsePolicy([]byte(text.String()))
	if r.Intn(4) == 0 {
		// Негодный файл обязан вести себя как observe.
		policy = ParsePolicy([]byte(pick("mode=deploy\n", "version=1\nmode=deploy\ncommands=shell\n", "\x00")))
	}

	in := observeInput{Policy: policy, Keys: r.Intn(2) == 0}
	in.HB = HeartbeatResponse{
		TargetAgentVersion:   pick("", "2.2.0", "2.3.0", "9.9.9", "1.0.0", "latest"),
		InventoryRequestedAt: pick("", "2026-09-23T10:00:00Z"),
	}
	if r.Intn(3) != 0 {
		in.HB.Task = &HostTask{ID: pick("", "t1", "t2"), Kind: kinds[r.Intn(len(kinds))], Project: "shop"}
	}
	switch r.Intn(3) {
	case 0:
		in.State.Apps = nil
	case 1:
		in.State.Apps = []DesiredApp{}
	default:
		in.State.Apps = []DesiredApp{{Slug: "shop", Desired: pick("present", "absent")}}
	}
	if r.Intn(2) == 0 {
		in.State.ObjectStorage = &ObjectStorageSpec{SecretKey: "s"}
	}
	return reflect.ValueOf(in)
}

// assertObserveExecutesNothing — свойство, ради которого режим существует
// (ADR-0095, п. 2 и 11): в observe хост не меняется, что бы ни прислали.
func assertObserveExecutesNothing(t *testing.T, in observeInput) bool {
	t.Helper()
	if in.Policy.Mode != PolicyModeObserve {
		t.Fatalf("вход не в режиме наблюдения: %+v", in.Policy)
	}
	plan := Decide(in.Policy, in.HB, in.State, in.Keys)
	ok := !plan.Apply && !plan.Recover && !plan.Storage && plan.Task == nil && plan.BaselineDrift
	if in.HB.Task != nil && (plan.Refused == nil || plan.RefuseReason == "") {
		ok = false
	}
	wantInventory := in.HB.InventoryRequestedAt != "" && in.Policy.allows("inventory")
	if plan.Inventory != wantInventory {
		ok = false
	}
	// Без ключа выпуска бинарь не проверяется подписью: в observe ни auto,
	// ни no_major, ни pinned не пускают обновиться — иначе взломанная платформа отдала бы
	// свой бинарь под закреплённым номером и сняла бы observe.
	if !in.Keys && plan.Updates.Kind != "manual" {
		ok = false
	}
	if AllowsSelfUpdate(in.Policy, "2.2.0", in.HB.TargetAgentVersion, in.Keys) {
		rule := in.Policy.DeployAgentUpdates
		legit := in.Keys && (rule.Kind == "auto" ||
			(rule.Kind == "no_major" && strings.HasPrefix(in.HB.TargetAgentVersion, "2.")) ||
			(rule.Kind == "pinned" && rule.Pin == in.HB.TargetAgentVersion))
		if !legit {
			ok = false
		}
	}
	if !ok {
		t.Errorf("observe исполняет: политика %+v, ответ %+v/%+v, ключи %v → план %+v",
			in.Policy, in.HB, in.State, in.Keys, plan)
	}
	return ok
}

func TestDecideObserveExecutesNothingOnAnyResponse(t *testing.T) {
	err := quick.Check(func(in observeInput) bool {
		return assertObserveExecutesNothing(t, in)
	}, &quick.Config{MaxCount: 2000})
	if err != nil {
		t.Fatal(err)
	}
}

// FuzzDecideObserve — тот же вопрос на произвольных байтах ответа такта.
// `go test -run FuzzDecideObserve` гоняет корпус-затравку; `-fuzz` — по желанию.
func FuzzDecideObserve(f *testing.F) {
	seeds := []struct {
		commands, updates, response string
		keys                        bool
	}{
		{"", "manual", `{}`, false},
		{"apply,backup,restore,export,migrate-data,start-stack,stop-stack,inventory", "auto",
			`{"apps":[{"slug":"shop","desired":"present"}],"task":{"id":"t1","kind":"backup"},"inventoryRequestedAt":"x","targetAgentVersion":"9.9.9","targetAgentSha256":{"amd64":"aa","arm64":"bb"},"objectStorage":{"secretKey":"s"}}`,
			false},
		{"inventory", "pinned 2.3.0", `{"apps":[],"task":{"id":"t2","kind":"restore"},"targetAgentVersion":"2.3.0"}`, true},
		{"inventory", "no_major", `{"apps":[],"targetAgentVersion":"3.0.0"}`, true},
		{"apply", "auto", `{"stateWithheld":"policy","task":null}`, true},
		{"backup", "pinned 1.0.0", `{"apps":null,"task":{"id":"","kind":"shell"}}`, false},
		{",,,", "manual", `not json`, true},
	}
	for _, s := range seeds {
		f.Add(s.commands, s.updates, s.response, s.keys)
	}
	f.Fuzz(func(t *testing.T, commands, updates, response string, keys bool) {
		text := "version=1\nmode=observe\ncommands=" + commands + "\ndeploy_agent_updates=" + updates + "\n"
		policy := ParsePolicy([]byte(text))
		var resp TickResponse
		// Неразборчивый ответ — тоже ответ: агент получает то, что получает.
		_ = json.Unmarshal([]byte(response), &resp)
		assertObserveExecutesNothing(t, observeInput{
			Policy: policy, HB: resp.HeartbeatResponse, State: resp.DesiredState, Keys: keys,
		})
	})
}

func TestPinnedAndManualUpdates(t *testing.T) {
	deploy := func(rule string) LocalPolicy {
		return ParsePolicy([]byte("version=1\nmode=deploy\ndeploy_agent_updates=" + rule + "\n"))
	}
	cases := []struct {
		name    string
		policy  LocalPolicy
		current string
		target  string
		keys    bool
		want    bool
	}{
		{"pinned: цель = пин и выше текущей — да", deploy("pinned 2.3.0"), "2.2.0", "2.3.0", true, true},
		{"pinned без ключа выпуска — как manual", deploy("pinned 2.3.0"), "2.2.0", "2.3.0", false, false},
		{"observe + pinned без ключа выпуска — как manual", ParsePolicy([]byte("version=1\ndeploy_agent_updates=pinned 2.3.0\n")), "2.2.0", "2.3.0", false, false},
		{"pinned: другая цель выше текущей — нет", deploy("pinned 2.3.0"), "2.2.0", "2.4.0", true, false},
		{"pinned: цель ниже пина — нет", deploy("pinned 2.3.0"), "2.2.0", "2.2.5", true, false},
		{"pinned: пин ниже текущей — нет", deploy("pinned 2.1.0"), "2.2.0", "2.1.0", true, false},
		{"pinned: пин равен текущей — нет", deploy("pinned 2.2.0"), "2.2.0", "2.2.0", true, false},
		{"manual: новее — нет", deploy("manual"), "2.2.0", "2.3.0", true, false},
		{"manual: мажор — нет", deploy("manual"), "2.2.0", "3.0.0", true, false},
		{"no_major: минорная — да", deploy("no_major"), "2.2.0", "2.3.0", true, true},
		{"no_major: смена MAJOR — нет", deploy("no_major"), "2.2.0", "3.0.0", true, false},
		{"no_major без ключа выпуска — как manual", deploy("no_major"), "2.2.0", "2.3.0", false, false},
		{"auto в deploy со всеми видами без ключа — да", deploy("auto"), "2.2.0", "2.3.0", false, true},
		{"auto в deploy с неполным списком без ключа — как manual", ParsePolicy([]byte("version=1\nmode=deploy\ncommands=backup\ndeploy_agent_updates=auto\n")), "2.2.0", "2.3.0", false, false},
		{"auto в deploy с неполным списком с ключом — да", ParsePolicy([]byte("version=1\nmode=deploy\ncommands=backup\ndeploy_agent_updates=auto\n")), "2.2.0", "2.3.0", true, true},
		{"observe + auto без ключа — как manual", ParsePolicy([]byte("version=1\ndeploy_agent_updates=auto\n")), "2.2.0", "2.3.0", false, false},
		{"observe + auto с ключом — да", ParsePolicy([]byte("version=1\ndeploy_agent_updates=auto\n")), "2.2.0", "2.3.0", true, true},
		{"негодный файл — нет", ParsePolicy([]byte("mode=deploy\n")), "2.2.0", "2.3.0", true, false},
		{"файла нет — решает прежняя проверка", LocalPolicy{State: PolicyAbsent}, "2.2.0", "2.3.0", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AllowsSelfUpdate(tc.policy, tc.current, tc.target, tc.keys); got != tc.want {
				t.Fatalf("AllowsSelfUpdate = %v, ожидалось %v (%+v)", got, tc.want, tc.policy.DeployAgentUpdates)
			}
		})
	}
	if reason := SelfUpdateRefusal(deploy("manual"), "2.2.0", "2.3.0", true); !strings.Contains(reason, "manual") {
		t.Fatalf("причина отказа не называет правило: %q", reason)
	}
	if reason := SelfUpdateRefusal(deploy("no_major"), "2.2.0", "3.0.0", true); !strings.Contains(reason, "no_major") ||
		!strings.Contains(reason, "3.0.0") {
		t.Fatalf("причина отказа смены MAJOR не названа: %q", reason)
	}
	if reason := SelfUpdateRefusal(deploy("no_major"), "2.2.0", "2.3.0", false); !strings.Contains(reason, "no_major") ||
		!strings.Contains(reason, "ключа выпуска") {
		t.Fatalf("причина отказа no_major без ключа не названа: %q", reason)
	}
	if reason := SelfUpdateRefusal(deploy("pinned 2.3.0"), "2.2.0", "2.3.0", false); !strings.Contains(reason, "pinned 2.3.0") ||
		!strings.Contains(reason, "ключа выпуска") {
		t.Fatalf("причина отказа пина без ключа не названа: %q", reason)
	}
}

// Действующее правило обновления — общая фикстура (раздел updateCases): её же
// исполняет агент мониторинга (monitor-push.sh), а платформа принимает доклад.
func TestEffectiveUpdatesMatchFixture(t *testing.T) {
	fx := loadHostPolicyFixture(t)
	if len(fx.UpdateCases) < 10 {
		t.Fatalf("в разделе updateCases %d случаев — проверка не проведена", len(fx.UpdateCases))
	}
	for _, c := range fx.UpdateCases {
		t.Run(c.Name, func(t *testing.T) {
			p := LocalPolicy{State: PolicyAbsent}
			if c.Text != nil {
				p = ParsePolicy([]byte(*c.Text))
			}
			if got := EffectiveDeployUpdates(p, c.ReleaseKeys).String(); got != c.DeployEffective {
				t.Fatalf("действующее deploy_agent_updates %q, в фикстуре %q", got, c.DeployEffective)
			}
		})
	}
}

// Пускает ли правило обновления с текущей на цель — общая фикстура (раздел
// permitCases): тот же вопрос решает monitor_update_permitted в
// monitor-push.sh. Ключи выпуска вшиты: здесь проверяется само правило, а не
// его замена на manual без подписи (это раздел updateCases).
func TestSelfUpdatePermitMatchesFixture(t *testing.T) {
	fx := loadHostPolicyFixture(t)
	if len(fx.PermitCases) < 10 {
		t.Fatalf("в разделе permitCases %d случаев — проверка не проведена", len(fx.PermitCases))
	}
	for _, c := range fx.PermitCases {
		t.Run(c.Name, func(t *testing.T) {
			p := ParsePolicy([]byte("version=1\nmode=deploy\ndeploy_agent_updates=" + c.Rule + "\n"))
			if p.State != PolicyValid {
				t.Fatalf("правило %q не разобрано: %s", c.Rule, p.Err)
			}
			if got := AllowsSelfUpdate(p, c.Current, c.Target, true); got != c.Permitted {
				t.Fatalf("%s: %s → %s — пускает %v, в фикстуре %v (%s)", c.Rule, c.Current, c.Target, got, c.Permitted,
					SelfUpdateRefusal(p, c.Current, c.Target, true))
			}
		})
	}
}

// Наблюдение без желаемого состояния: здоровье опрашивается по тому, что агент
// применял сам, — иначе в observe платформа не получала бы здоровья вовсе.
func TestBaselineAppsFromApplied(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	if got := BaselineApps(p); len(got) != 0 {
		t.Fatalf("без applied.json приложения %+v", got)
	}
	applied := `{"apps":{"shop":{"release_id":"r1"},"../etc":{"release_id":"r2"},"blog":{"release_id":"r3"}}}`
	if err := os.WriteFile(filepath.Join(p.StateDir, "applied.json"), []byte(applied), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(p.WorkDir, "apps", "shop")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DB_PASSWORD='s3cr3t-value'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := BaselineApps(p)
	if len(got) != 2 || got[0].Slug != "blog" || got[1].Slug != "shop" || !got[1].ShouldRun() {
		t.Fatalf("приложения базовой линии %+v", got)
	}
	// Значения .env нужны только затиранию вывода docker перед отправкой.
	if redactSecrets("ошибка: s3cr3t-value", got[1].redactionValues()) == "ошибка: s3cr3t-value" {
		t.Fatal("значение из .env не затирается в выводе, уходящем на платформу")
	}
}

// Дрейф в наблюдении сверяется без желаемого — только с базовой линией
// applied.json (ADR-0095, п. 2). Решено тестом, а не догадкой: ложных сигналов
// это не даёт, а чужую правку видно.
//
// Толкование у правки в наблюдении — foreign_over_pending, а не foreign:
// без желаемого сверка не может доказать, что применённое «устоялось».
// Инцидент платформа поднимает на оба (integrityIncidents.ts: всё, кроме
// in_transit), так что сигнал не теряется; список из applied.json этого не
// исправил бы — отпечаток конфигурации из отметок не восстановить.
func TestObserveDriftBaselineOnly(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	deployFiles(t, p, app, app.Compose, true)

	// Такт в deploy: сверка с желаемым, последнее известное зафиксировано.
	records, commit := observe(t, p, []DesiredApp{app})
	mustDrift(t, records, "compose", app.Slug, "match", "")
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	applied, _ := os.ReadFile(appliedPath(p))

	// Переход в observe: желаемого нет — сигналов нет, базовая линия цела.
	records, commit = observe(t, p, nil)
	if len(records) != 0 {
		t.Fatalf("без желаемого — ложные сигналы: %+v", records)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if now, _ := os.ReadFile(appliedPath(p)); string(now) != string(applied) {
		t.Fatalf("сверка в наблюдении переписала базовую линию:\n%s", now)
	}

	// Чужая правка в наблюдении видна.
	composePath := filepath.Join(p.appDir(app.Slug), "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(app.Compose+"    privileged: true\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	records, _ = observe(t, p, nil)
	if len(records) != 1 {
		t.Fatalf("правка compose в наблюдении: %+v", records)
	}
	mustDrift(t, records, "compose", app.Slug, "mismatch", "foreign_over_pending")

	// Первое наблюдение сразу в observe (новая установка поверх старой
	// базовой линии): совпадение — не инцидент.
	fresh := testPaths(t)
	deployFiles(t, fresh, app, app.Compose, true)
	records, _ = observe(t, fresh, nil)
	for _, r := range records {
		if r.Status == "mismatch" || r.Status == "missing" {
			t.Fatalf("совпадающий диск дал сигнал правки: %+v", r)
		}
	}
}

// Нулевой байт где угодно, даже в комментарии, — негодный файл: bash-агент
// мониторинга не держит NUL в переменной и прочитал бы другой текст, а три
// разбора обязаны видеть один и тот же.
func TestPolicyNulByteIsInvalid(t *testing.T) {
	for name, text := range map[string]string{
		"в комментарии":        "version=1\nmode=deploy\n# a\x00b\n",
		"в значении":           "version=1\nmode=deploy\x00\n",
		"в хвосте после строк": "version=1\nmode=observe\n\x00",
	} {
		t.Run(name, func(t *testing.T) {
			assertClosed(t, ParsePolicy([]byte(text)))
			path := filepath.Join(t.TempDir(), "agent-policy.conf")
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			assertClosed(t, LoadLocalPolicyFrom(path))
		})
	}
}

// «Политики нет» — только когда нет самой записи в каталоге. Запись есть, но
// не читается — негодный файл: владелец что-то положил, и открывать прежнее
// поведение по его ошибке нельзя.
func TestPolicyUnreadableEntryIsNotAbsent(t *testing.T) {
	t.Run("висячая символическая ссылка", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "agent-policy.conf")
		if err := os.Symlink(filepath.Join(dir, "nowhere.conf"), path); err != nil {
			t.Fatal(err)
		}
		got := LoadLocalPolicyFrom(path)
		assertClosed(t, got)
		if got.Protected {
			t.Fatal("символическая ссылка признана защищённой")
		}
	})
	t.Run("lstat отказал не ENOENT", func(t *testing.T) {
		prev := policyLstat
		policyLstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		t.Cleanup(func() { policyLstat = prev })
		assertClosed(t, LoadLocalPolicyFrom(filepath.Join(t.TempDir(), "agent-policy.conf")))
	})
}
