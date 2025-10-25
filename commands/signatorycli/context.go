package signatorycli

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/signatory-io/signatory-core/signer/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	defaultBaseDir      = ".signatory-cli"
	defaultHost         = "localhost"
	defaultConfig       = "config.yaml"
	defaultIdentityFile = "id_key"
)

type Config struct {
	BasePath    string `yaml:"base_path"`
	RPCEndpoint string `yaml:"rpc_endpoint"`
}

func (c *Config) GetBasePath() string { return c.BasePath }

func LoadConfig(conf *Config, path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(buf, conf)
}

func DefaultConfig() *Config {
	dir, _ := os.UserHomeDir()
	return &Config{
		BasePath:    filepath.Join(dir, defaultBaseDir),
		RPCEndpoint: fmt.Sprintf("tcp://%s:%d", defaultHost, api.DefaultPort),
	}
}

func LoadConfigFromCmdline(conf *Config, f *pflag.FlagSet) error {
	baseDir, err := f.GetString("base-dir")
	if err != nil {
		panic(err)
	}
	confPath, err := f.GetString("config-file")
	if err != nil {
		panic(err)
	}
	if err := LoadConfig(conf, getPath(confPath, baseDir)); err != nil {
		return err
	}
	if f.Changed("base-dir") {
		conf.BasePath = baseDir
	}
	if f.Changed("rpc-address") {
		rpcAddr, err := f.GetString("rpc-address")
		if err != nil {
			panic(err)
		}
		conf.RPCEndpoint = rpcAddr
	}
	// add default RPC identity file
	u, err := url.Parse(conf.RPCEndpoint)
	if err != nil {
		return nil
	}
	if u.Scheme == "secure" && u.Fragment == "" {
		u.Fragment = defaultIdentityFile
		conf.RPCEndpoint = u.String()
	}
	return nil
}

func (c *Config) RegisterFlags(f *pflag.FlagSet, cmd *cobra.Command) {
	f.StringP("base-dir", "b", c.BasePath, "Base directory")
	f.StringP("config-file", "c", defaultConfig, "Configuration file path (absolute or relative to the base directory)")
	f.StringP("rpc-address", "r", c.RPCEndpoint, "RPC endpoint address, format: transport://[host]:port[#identity], where transport is [tcp, secure, http], and identity is a key file for secure connection")

	cmd.MarkFlagFilename("config-file")
	cmd.MarkFlagDirname("base-dir")
}
