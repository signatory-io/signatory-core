package core

import (
	"iter"
	"maps"
	"net/url"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/signatory-io/signatory-core/logger"
	"github.com/signatory-io/signatory-core/signer"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Config struct {
	BasePath   string                   `yaml:"base_path"`
	RPCAddress string                   `yaml:"rpc_address"` // transport://[host]:port[#identity], where transport is [tcp, secure, http], and identity is a key file for secure connection
	LogLevel   logger.Level             `yaml:"log_level"`
	Vaults     map[string]*vault.Config `yaml:"vaults,omitempty"`
}

type CoreConfig interface {
	Default()
	FromCmdline(loadFromFile bool, flags *pflag.FlagSet) error
	SetBasePath(path string)
	GetBasePath() string
	SetRPCAddress(path string)
	SetLogLevel(level logger.Level)
	GetRPCAddress() string
}

func (c *Config) GetBasePath() string                         { return c.BasePath }
func (c *Config) SetBasePath(path string)                     { c.BasePath = path }
func (c *Config) GetRPCAddress() string                       { return c.RPCAddress }
func (c *Config) SetRPCAddress(address string)                { c.RPCAddress = address }
func (c *Config) GetVaults() iter.Seq2[string, *vault.Config] { return maps.All(c.Vaults) }
func (c *Config) SetLogLevel(level logger.Level)              { c.LogLevel = level }

func LoadConfig[T any](conf T, path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(buf, conf)
}

const (
	DefaultConfigFile   = "config.yaml"
	DefaultIdentityFile = "id_key"
)

func (conf *Config) RegisterFlags(f *pflag.FlagSet, cmd *cobra.Command) {
	f.StringP("base-dir", "b", conf.BasePath, "Base directory")
	f.StringP("config-file", "c", DefaultConfigFile, "Configuration file path (absolute or relative to the base directory)")
	f.StringP("rpc-address", "r", conf.RPCAddress, "RPC listening address, format: transport://[host]:port[#identity], where transport is [tcp, secure, http], and identity is a key file for secure connection")
	f.TextVarP(&conf.LogLevel, "log-level", "l", conf.LogLevel, "Log level: [error, warn, info, debug, trace]")

	cmd.MarkFlagFilename("config-file")
	cmd.MarkFlagDirname("base-dir")
}

func LoadCoreConfigFromCmdline[T CoreConfig](conf T, loadFromFile bool, f *pflag.FlagSet) error {
	baseDir, err := f.GetString("base-dir")
	if err != nil {
		panic(err)
	}
	if loadFromFile {
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
	if f.Changed("log-level") {
		var level logger.Level
		if err := f.GetText("log-level", &level); err != nil {
			return err
		}
		conf.SetLogLevel(level)
	}

	// add default RPC identity file
	rpcAddr := conf.GetRPCAddress()
	u, err := url.Parse(rpcAddr)
	if err != nil {
		return err
	}
	if u.Scheme == "secure" && u.Fragment == "" {
		u.Fragment = DefaultIdentityFile
		conf.SetRPCAddress(u.String())
	}

	return nil
}

var (
	_ signer.Config = (*Config)(nil)
)
