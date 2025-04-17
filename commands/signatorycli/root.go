package signatorycli

import (
	"fmt"

	"github.com/signatory-io/signatory-core/rpc/signatory"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	var conf RootContextConfig

	cmd := cobra.Command{
		Use:   "signatory-cli [options]",
		Short: "Signatory RPC client",
	}

	conf.Flags = cmd.PersistentFlags()
	conf.Flags.StringVarP(&conf.BaseDir, "base-dir", "b", "", fmt.Sprintf("Base directory (default is ~/%s)", defaultBaseDir))
	conf.Flags.StringVarP(&conf.ConfigFile, "config-file", "c", "", "Configuration file path")
	conf.Flags.StringVarP(&conf.Endpoint, "endpoint", "e", "", fmt.Sprintf("RPC endpoint address (default is %s:%d for plain text connection and %s:%d for secure one)", defaultHost, signatory.DefaultPort, defaultHost, signatory.DefaultSecurePort))
	conf.Flags.BoolVarP(&conf.Secure, "secure-connection", "s", false, "Use encrypted and authenticated secure connection")
	conf.Flags.StringVar(&conf.Identity, "identity-file", "", "Secure connection identity key file")

	cmd.AddCommand(NewConfigCommand(&conf))

	return &cmd
}
