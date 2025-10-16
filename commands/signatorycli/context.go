package signatorycli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc/signatory"
	"github.com/signatory-io/signatory-core/utils"
	"github.com/spf13/pflag"
)

const (
	defaultBaseDir = ".signatory-cli"
	defaultHost    = "localhost"
	defaultConfig  = "config.yaml"
	identityFile   = "id_key"
)

type configFile struct {
	Endpoint string `yaml:"endpoint"`
	Secure   bool   `yaml:"secure"`
}

type RootContextConfig struct {
	BaseDir    string
	ConfigFile string
	Endpoint   string
	Secure     bool
	Identity   string
	Flags      *pflag.FlagSet
}

type RootContext struct {
	BaseDir  string
	Endpoint string
	Identity *ed25519.PrivateKey
}

func (r *RootContextConfig) NewContext() (*RootContext, error) {
	ctx := RootContext{
		BaseDir: r.GetBaseDir(),
	}
	var secure bool
	buf, err := os.ReadFile(r.GetConfigFile())
	if err == nil {
		var conf configFile
		if err = yaml.Unmarshal(buf, &conf); err != nil {
			return nil, err
		}

		ctx.Endpoint = conf.Endpoint
		if r.Endpoint != "" && r.Flags.Changed("endpoint") {
			ctx.Endpoint = r.Endpoint
		}

		secure = conf.Secure
		if r.Flags.Changed("secure-connection") {
			secure = r.Secure
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		ctx.Endpoint = r.GetEndpoint()
	}
	if secure {
		id, err := utils.LoadIdentity(r.GetIdentityFile())
		if err != nil {
			return nil, err
		}
		ctx.Identity = id
	}
	return &ctx, nil
}

func (r *RootContextConfig) GetBaseDir() string {
	if r.BaseDir == "" {
		dir, _ := os.UserHomeDir()
		return filepath.Join(dir, defaultBaseDir)
	}
	return r.BaseDir
}

func (r *RootContextConfig) GetConfigFile() string {
	if r.ConfigFile == "" {
		return filepath.Join(r.GetBaseDir(), defaultConfig)
	}
	return r.ConfigFile
}

func (r *RootContextConfig) GetIdentityFile() string {
	if r.Identity == "" {
		return filepath.Join(r.GetBaseDir(), identityFile)
	}
	return r.Identity
}

func (r RootContextConfig) GetEndpoint() string {
	if r.Endpoint == "" {
		var port uint
		if r.Secure {
			port = signatory.DefaultSecurePort
		} else {
			port = signatory.DefaultPort
		}
		return fmt.Sprintf("%s:%d", defaultHost, port)
	}
	return r.Endpoint
}
