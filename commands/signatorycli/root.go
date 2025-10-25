package signatorycli

import (
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "signatory-cli [options]",
		Short: "Signatory RPC client",
	}

	conf := DefaultConfig()
	conf.RegisterFlags(cmd.PersistentFlags(), &cmd)

	cmd.AddCommand(newConfigCommand())
	cmd.AddCommand(newVaultCommand())
	cmd.AddCommand(newKeyCommand())

	return &cmd
}
