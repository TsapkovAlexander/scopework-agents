// Package agent — ядро агента платформы развёртывания Scopework.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity — постоянная личность агента на этом хосте.
//
// Приватный ключ генерируется здесь при установке и никогда не покидает
// сервер: наружу уходит только публичный. Поэтому компрометация нашей стороны
// не даёт возможности выдать себя за агента, а копия конфига, снятая со
// взломанного хоста, бесполезна без файла ключа.
type Identity struct {
	PublicKey  string `json:"public_key"`  // base64 сырых 32 байт Ed25519
	PrivateKey string `json:"private_key"` // base64 сырых 64 байт seed+public
}

// Fingerprint — SHA-256 от строки публичного ключа в hex.
//
// Считается ровно так же на сервере (см. api/deploy/agent/enroll): сервер
// пересчитывает отпечаток из присланного ключа и отвергает несовпадение,
// чтобы агент не мог занять чужой отпечаток.
func (id Identity) Fingerprint() string {
	sum := sha256.Sum256([]byte(id.PublicKey))
	return hex.EncodeToString(sum[:])
}

func (id Identity) signer() (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать приватный ключ: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("неверный размер приватного ключа: %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// Sign подписывает произвольные данные приватным ключом агента.
//
// В Фазе 0 heartbeat опознаётся только отпечатком, и подпись ещё не
// используется. Она понадобится, как только в желаемом состоянии появятся
// секреты приложений: тогда сервер обязан убедиться, что запрос пришёл от
// владельца ключа, а не от того, кто узнал отпечаток.
func (id Identity) Sign(payload []byte) (string, error) {
	key, err := id.signer()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)), nil
}

// NewIdentity создаёт новую пару ключей.
func NewIdentity() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("не удалось сгенерировать ключ: %w", err)
	}
	return Identity{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, nil
}

// LoadIdentity читает личность с диска.
func LoadIdentity(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return Identity{}, fmt.Errorf("повреждён файл ключа %s: %w", path, err)
	}
	if id.PublicKey == "" || id.PrivateKey == "" {
		return Identity{}, fmt.Errorf("файл ключа %s неполон", path)
	}
	return id, nil
}

// SaveIdentity пишет личность на диск с правами 0600.
//
// Запись идёт через временный файл рядом с целевым и переименование: так на
// диске никогда не окажется наполовину записанного ключа, даже если процесс
// убьют в этот момент.
func SaveIdentity(path string, id Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
