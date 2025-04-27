package auth

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"

	cosekey "github.com/signatory-io/signatory-core/crypto/cose/key"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc/conn/secure"
	"github.com/signatory-io/signatory-core/utils"
	"gopkg.in/yaml.v3"
)

type KeysFile string

func Read(name string) ([]*ed25519.PublicKey, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var lines []string
	if err := yaml.Unmarshal(data, &lines); err != nil {
		return nil, err
	}
	out := make([]*ed25519.PublicKey, len(lines))
	for i, l := range lines {
		keyData, err := hex.DecodeString(l)
		if err != nil {
			return nil, err
		}
		tmp, err := cosekey.ParsePublicKey(keyData)
		if err != nil {
			return nil, err
		}
		pub, ok := tmp.(*ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("auth: unexpected public key type %T", tmp)
		}
		out[i] = pub
	}
	return out, nil
}

func Write(name string, keys []*ed25519.PublicKey) error {
	data, err := yaml.Marshal(keys)
	if err != nil {
		return err
	}
	return utils.AtomicWrite(name, data, 0600)
}

func (k KeysFile) IsAuthenticatedPeerAllowed(remoteAddr net.Addr, authenticatedRemoteKey *ed25519.PublicKey) bool {
	keys, err := Read(string(k))
	if err != nil {
		return false
	}
	for _, k := range keys {
		if *k == *authenticatedRemoteKey {
			return true
		}
	}
	return false
}

func (k KeysFile) IsConnectionAllowed(remoteAddr net.Addr, unauthenticatedRemoteKey *ed25519.PublicKey) bool {
	return true
}

var _ secure.Authenticator = KeysFile("")
