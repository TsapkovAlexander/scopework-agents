package agent

import (
	"os"
	"testing"
)

func TestDetectPrivilegeModeTrebuetOboihUslovij(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("прогон от root: режим здесь всегда root, проверять нечего")
	}

	t.Setenv("DOCKER_HOST", "")
	// Непривилегированный пользователь БЕЗ прокси — это пользователь в группе
	// docker, то есть те же права root. Считать такой хост переведённым
	// значило бы показать клиенту зелёную отметку там, где ничего не менялось.
	if got := DetectPrivilegeMode(); got != PrivilegeModeRoot {
		t.Fatalf("без прокси режим %q, ожидался %q", got, PrivilegeModeRoot)
	}

	t.Setenv("DOCKER_HOST", "unix:///run/tracedocs/docker-proxy.sock")
	if got := DetectPrivilegeMode(); got != PrivilegeModeProxy {
		t.Fatalf("с прокси режим %q, ожидался %q", got, PrivilegeModeProxy)
	}
}
