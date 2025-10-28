package signatorycli

import (
	corecmd "github.com/signatory-io/signatory-core/commands/core"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "signatory-cli [options]",
		Short: "Signatory RPC client",
	}

	var conf Config
	conf.Default()
	conf.RegisterFlags(cmd.PersistentFlags(), &cmd)

	cmd.AddCommand(newConfigCommand())
	cmd.AddCommand(newVaultCommand())
	cmd.AddCommand(newKeyCommand())

	return &cmd
}

func newConfigCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "config",
		Aliases: []string{"conf"},
		Short:   "signatory-cli configuration commands",
	}
	cmd.AddCommand(corecmd.NewConfigInitCommand[Config]())
	cmd.AddCommand(corecmd.NewIDCommand())
	return &cmd
}
