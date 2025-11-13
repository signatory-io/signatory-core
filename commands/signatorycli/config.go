package signatorycli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/signatory-io/signatory-core/core"
	"github.com/signatory-io/signatory-core/logger"
	"github.com/signatory-io/signatory-core/signer/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	defaultBaseDir = ".signatory-cli"
)

type Config struct {
	BasePath    string       `yaml:"base_path"`
	LogLevel    logger.Level `yaml:"log_level"`
	RPCEndpoint string       `yaml:"rpc_endpoint"`
}

var _ core.CoreConfig = (*Config)(nil)

func (c *Config) GetBasePath() string            { return c.BasePath }
func (c *Config) SetBasePath(path string)        { c.BasePath = path }
func (c *Config) GetRPCAddress() string          { return c.RPCEndpoint }
func (c *Config) SetRPCAddress(address string)   { c.RPCEndpoint = address }
func (c *Config) SetLogLevel(level logger.Level) { c.LogLevel = level }

func (c *Config) Default() {
	dir, _ := os.UserHomeDir()
	*c = Config{
		BasePath:    filepath.Join(dir, defaultBaseDir),
		RPCEndpoint: fmt.Sprintf("tcp://%s:%d", api.DefaultHost, api.DefaultPort),
		LogLevel:    logger.LevelInfo,
	}
}

func (conf *Config) FromCmdline(fromFile bool, f *pflag.FlagSet) error {
	return core.LoadCoreConfigFromCmdline(conf, true, f)
}

func (c *Config) RegisterFlags(f *pflag.FlagSet, cmd *cobra.Command) {
	f.StringP("base-dir", "b", c.BasePath, "Base directory")
	f.StringP("config-file", "c", core.DefaultConfigFile, "Configuration file path (absolute or relative to the base directory)")
	f.StringP("rpc-address", "r", c.RPCEndpoint, "RPC endpoint address, format: transport://[host]:port[#identity], where transport is [tcp, secure, http], and identity is a key file for secure connection")
	f.TextVarP(&c.LogLevel, "log-level", "l", c.LogLevel, "Log level: [error, warn, info, debug, trace]")

	cmd.MarkFlagFilename("config-file")
	cmd.MarkFlagDirname("base-dir")
}
