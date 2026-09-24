package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

// Guard стоит в applyOne на КАЖДОМ источнике, а не только на клиентском
// (задача С1.5).
//
// TestGuardAppliesToPlatformSources проверял только саму политику: та же модель
// отбивается независимо от источника. Возврат условия
// `if app.UntrustedCompose()` вокруг вызова guard он не ловил — политика
// осталась бы прежней, просто до неё не доходило бы. Здесь проверяется место
// вызова: шаблон каталога, рендер образа и «свой compose» с моделью вне
// политики до подъёма не доходят.

// stubComposeConfig подменяет нормализованный вид: без настоящего docker
// модели с `privileged` взяться неоткуда.
func stubComposeConfig(t *testing.T, model string) {
	t.Helper()
	prev := composeConfig
	composeConfig = func(context.Context, composeTarget) (string, error) { return model, nil }
	t.Cleanup(func() { composeConfig = prev })
}

func TestApplyOneGuardsEveryLocalSource(t *testing.T) {
	stubComposeConfig(t, `{"services":{"app":{"image":"nginx","privileged":true}}}`)

	for _, source := range []string{"template", "image", "compose"} {
		t.Run(source, func(t *testing.T) {
			// Поддельный docker — только чтобы увидеть, что подъёма не было:
			// guard обязан отказать раньше любого обращения к стеку.
			calls := installFakeDocker(t, "")
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			app := DesiredApp{
				Slug:       "shop",
				SourceType: source,
				Compose:    "services:\n  app:\n    image: nginx\n    privileged: true\n",
				ApplySpec:  ApplySpec{StableChecks: 1},
			}

			var written AppliedRecord
			_, err := applyOne(context.Background(), p, app, func(string, string) {}, &written)
			if err == nil || !strings.Contains(err.Error(), "описание стека отклонено") {
				t.Fatalf("источник %s: стек вне политики не отклонён: %v\nвызовы docker:\n%s",
					source, err, describeCalls(calls()))
			}
			if !strings.Contains(err.Error(), "privileged") {
				t.Errorf("отказ не называет правило: %v", err)
			}
			for _, c := range calls() {
				if c.hasArg("up") || c.hasArg("build") {
					t.Errorf("источник %s: стек поднимался после отказа guard: docker %s", source, c.line())
				}
			}
		})
	}
}

// Послабления политики доходят до guard только из проверенного гранта корня
// (С1.5, ADR-0092, решение 11). Всё, что пришло полем ответа, — данные
// платформы, а ей выход за политику не положен.

// smtpPortsModel — нормализованный стек с прямым портом 25: без послабления
// его отбивает правило ports.
const smtpPortsModel = `{"services":{"smtp":{"image":"example/mail:1",` +
	`"ports":[{"mode":"ingress","target":25,"published":"25","protocol":"tcp"}]}}}`

const (
	mailCompose  = "services:\n  smtp:\n    image: example/mail:1\n    ports:\n      - \"25:25\"\n"
	relayCompose = "services:\n  smtp:\n    image: example/relay:1\n    ports:\n      - \"25:25\"\n"
)

func smtpAllowances() []composeguard.Allowance {
	return []composeguard.Allowance{{Kind: composeguard.AllowPublishPort, Service: "smtp", Port: 25, Protocol: "tcp"}}
}

// guardVerdict прогоняет applyOne до guard и возвращает его отказ; nil —
// guard пропустил. Контекст гасится в момент нормализации: дальше guard
// работает без контекста, а следующий шаг после него — первая команда docker —
// падает на погашенном контексте, так что стек не поднимается ни в каком
// исходе.
func guardVerdict(t *testing.T, app DesiredApp) error {
	t.Helper()
	installFakeDocker(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := composeConfig
	normalized := false
	composeConfig = func(context.Context, composeTarget) (string, error) {
		normalized = true
		cancel()
		return smtpPortsModel, nil
	}
	t.Cleanup(func() { composeConfig = prev })

	app.ApplySpec = ApplySpec{StableChecks: 1}
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	var written AppliedRecord
	_, err := applyOne(ctx, p, app, func(string, string) {}, &written)
	if !normalized {
		t.Fatalf("applyOne не дошёл до guard: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "описание стека отклонено") {
		return err
	}
	return nil
}

func TestAllowanceWithoutSignedGrantNotApplied(t *testing.T) {
	useStateRoots(t, "")
	w := newStateWorld(t)
	compose, _ := json.Marshal(mailCompose)
	// Похоже на грант, но едет полем приложения в неподписанном ответе.
	_, url := newFakePlatform(t, `{"apps":[{"slug":"mail","sourceType":"template","compose":`+string(compose)+
		`,"allowances":[{"kind":"publish_port","service":"smtp","port":25,"protocol":"tcp"}],`+
		`"grants":[{"composeSha256":"`+testHex(mailCompose)+`"}]}]}`)

	resp := w.tick(t, w.client(url, t.TempDir()))
	if !resp.DesiredState.Accepted || len(resp.Apps) != 1 {
		t.Fatalf("неподписанное состояние не принято: %+v", resp.DesiredState)
	}
	if resp.Apps[0].Allowances != nil {
		t.Fatalf("послабление из поля ответа дошло до приложения: %+v", resp.Apps[0].Allowances)
	}
	err := guardVerdict(t, resp.Apps[0])
	if err == nil || !strings.Contains(err.Error(), "ports") {
		t.Fatalf("ports без подписанного гранта не отклонён: %v", err)
	}
}

func TestSignedGrantAllowsOnlyItsCompose(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	mail, _ := json.Marshal(mailCompose)
	relay, _ := json.Marshal(relayCompose)
	state := `{"apps":[` +
		`{"slug":"mail","sourceType":"template","compose":` + string(mail) + `},` +
		`{"slug":"relay","sourceType":"template","compose":` + string(relay) + `},` +
		// git-приложение с тем же digest пустого compose гранта не получает:
		// его описание стека читается из репозитория, а не из подписанного.
		`{"slug":"repo","sourceType":"git","compose":""}` +
		`],"registries":[],"denyIps":[]}`

	grant, err := hoststate.IssueGrant(w.root, testHex(mailCompose), smtpAllowances(), "почта: SMTP на 25/tcp")
	if err != nil {
		t.Fatal(err)
	}
	emptyGrant, err := hoststate.IssueGrant(w.root, testHex(""), smtpAllowances(), "пустой compose")
	if err != nil {
		t.Fatal(err)
	}
	signed := signedStateField(t, hoststate.ContentV0,
		w.signStateAs(t, w.work, 5, state, []string{}, grant, emptyGrant), w.cert(t), map[string]string{})
	_, url := newFakePlatform(t, signedResponse(signed))

	resp := w.tick(t, w.client(url, t.TempDir()))
	if !resp.DesiredState.Accepted || len(resp.Apps) != 3 {
		t.Fatalf("пакет с грантом не принят: %+v", resp.DesiredState)
	}
	byslug := map[string]DesiredApp{}
	for _, a := range resp.Apps {
		byslug[a.Slug] = a
	}
	if !reflect.DeepEqual(byslug["mail"].Allowances, smtpAllowances()) {
		t.Fatalf("послабления mail: %+v", byslug["mail"].Allowances)
	}
	if byslug["relay"].Allowances != nil || byslug["repo"].Allowances != nil {
		t.Fatalf("грант достался чужому compose: relay %+v, repo %+v",
			byslug["relay"].Allowances, byslug["repo"].Allowances)
	}

	if err := guardVerdict(t, byslug["mail"]); err != nil {
		t.Fatalf("guard отклонил стек с подписанным грантом: %v", err)
	}
	if err := guardVerdict(t, byslug["relay"]); err == nil || !strings.Contains(err.Error(), "ports") {
		t.Fatalf("ports у соседа без гранта не отклонён: %v", err)
	}
}
