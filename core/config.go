package core

import (
	"fmt"
	"iter"
	"maps"
	"net/url"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/signatory-io/signatory-core/signer"
	signerapi "github.com/signatory-io/signatory-core/signer/api"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/spf13/pflag"
)

type Config struct {
	BasePath   string                   `yaml:"base_path"`
	RPCAddress string                   `yaml:"rpc_address"` // transport://[host]:port[#identity], where transport is [tcp, secure, http], and identity is a key file for secure connection
	Vaults     map[string]*vault.Config `yaml:"vaults"`
}

type CoreConfig interface {
	SetBasePath(path string)
	SetRPCAddress(path string)
	GetRPCAddress() string
}

func (c *Config) GetBasePath() string {
	return c.BasePath
}

func (c *Config) SetBasePath(path string) {
	c.BasePath = path
}

func (c *Config) GetRPCAddress() string {
	return c.RPCAddress
}

func (c *Config) SetRPCAddress(address string) {
	c.RPCAddress = address
}

func (c *Config) GetVaults() iter.Seq2[string, *vault.Config] {
	return maps.All(c.Vaults)
}

func LoadConfig[T CoreConfig](conf T, path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(buf, conf)
}

const (
	defaultBaseDir = ".signatory-evm"
	defaultHost    = "localhost"
	defaultConfig  = "config.yaml"
	identityFile   = "id_key"
)

func DefaultConfig() *Config {
	dir, _ := os.UserHomeDir()
	return &Config{
		BasePath:   filepath.Join(dir, defaultBaseDir),
		RPCAddress: fmt.Sprintf("tcp://%s:%d", defaultHost, signerapi.DefaultPort),
	}
}

func (conf *Config) RegisterFlags(f *pflag.FlagSet) {
	f.StringP("base-dir", "b", conf.BasePath, "Base directory")
	f.StringP("config-file", "c", defaultConfig, "Configuration file path (absolute or relative to the base directory)")
	f.StringP("rpc-address", "r", conf.RPCAddress, "RPC listening address, format: transport://[host]:port[#identity], where transport is [tcp, secure, http], and identity is a key file for secure connection")
}

func LoadConfigFromCmdline[T CoreConfig](conf T, f *pflag.FlagSet) error {
	baseDir, err := f.GetString("base-dir")
	if err != nil {
		panic(err)
	}
	confPath, err := f.GetString("config-file")
	if err != nil {
		panic(err)
	}
	if !filepath.IsAbs(confPath) {
		confPath = filepath.Join(baseDir, confPath)
	}
	if err := LoadConfig(conf, confPath); err != nil {
		return err
	}
	if f.Changed("base-dir") {
		conf.SetBasePath(baseDir)
	}
	if f.Changed("rpc-address") {
		rpcAddr, err := f.GetString("rpc-address")
		if err != nil {
			panic(err)
		}
		conf.SetRPCAddress(rpcAddr)
	}

	// add default RPC identity file
	rpcAddr := conf.GetRPCAddress()
	u, err := url.Parse(rpcAddr)
	if err != nil {
		return nil
	}
	if u.Scheme == "secure" && u.Fragment == "" {
		u.Fragment = identityFile
		conf.SetRPCAddress(u.String())
	}

	return nil
}

var (
	_ signer.Config = (*Config)(nil)
	_ CoreConfig    = (*Config)(nil)
)
