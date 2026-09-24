package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComposeGuardSymlinkNesushchestvuyushchiyHvost(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "l", "newdir")
	v, err := checkComposeSafety([]byte(`{"services":{"app":{"volumes":[{"type":"bind","source":"`+src+`","target":"/h"}]}}}`), []string{root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 {
		t.Fatalf("guard пропустил %s: ссылка наружу, хвоста на диске нет", src)
	}
}
