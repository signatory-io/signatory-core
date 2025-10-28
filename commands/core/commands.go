package core

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/signatory-io/signatory-core/core"
	"github.com/signatory-io/signatory-core/signer/api"
	"github.com/signatory-io/signatory-core/utils"
	"github.com/spf13/cobra"
)

func NewConfigInitCommand[T any, P interface {
	core.CoreConfig
	*T
}]() *cobra.Command {
	var (
		secure      bool
		genIdentity bool
	)

	cmd := cobra.Command{
		Use:   "init",
		Short: "Create new configuration file with provided parameters",
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			var placeholder T
			var conf P = &placeholder
			conf.Default()

			if err := conf.FromCmdline(false, f); err != nil {
				return err
			}
			if !f.Changed("rpc-address") && secure {
				conf.SetRPCAddress(fmt.Sprintf("secure://%s:%d#%s", api.DefaultHost, api.DefaultSecurePort, core.DefaultIdentityFile))
			}

			buf, err := yaml.Marshal(&conf)
			if err != nil {
				return err
			}

			confPath, err := f.GetString("config-file")
			if err != nil {
				panic(err)
			}
			confPath = core.GetPath(confPath, conf.GetBasePath())

			dir := filepath.Dir(confPath)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			if err := os.WriteFile(confPath, buf, 0600); err != nil {
				return err
			}
			fmt.Printf("Configuration file %s is successfully created\n", confPath)

			u, err := url.Parse(conf.GetRPCAddress())
			if err != nil {
				return err
			}
			if u.Scheme == "secure" && genIdentity {
				return core.GenerateIdentityKey(core.GetPath(u.Fragment, conf.GetBasePath()))
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&secure, "secure-rpc", "s", false, fmt.Sprintf("Set the default RPC address to `secure://%s:%d#%s'. Does nothing if the endpoint is explicitly specified", api.DefaultHost, api.DefaultSecurePort, core.DefaultIdentityFile))
	f.BoolVarP(&genIdentity, "gen-identity", "i", true, "Generate a new identity file if secure connection is requested")

	return &cmd
}

func NewIDCommand() *cobra.Command {
	var keyFile string

	cmd := cobra.Command{
		Use:     "identity",
		Aliases: []string{"id"},
		Short:   "Secure connection identity key management commands",
	}

	genCmd := cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate the new identity key",
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			baseDir, err := f.GetString("base-dir")
			if err != nil {
				panic(err)
			}
			return core.GenerateIdentityKey(core.GetPath(keyFile, baseDir))
		},
	}

	printCmd := cobra.Command{
		Use:     "print",
		Aliases: []string{"p"},
		Short:   "Print the public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			baseDir, err := f.GetString("base-dir")
			if err != nil {
				panic(err)
			}
			priv, err := utils.LoadIdentity(core.GetPath(keyFile, baseDir))
			if err != nil {
				return err
			}
			fmt.Println(hex.EncodeToString(priv.Public().COSE().Encode()))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&keyFile, "identity-key", "i", core.DefaultIdentityFile, "Identity key file")

	cmd.AddCommand(&genCmd)
	cmd.AddCommand(&printCmd)
	return &cmd
}
