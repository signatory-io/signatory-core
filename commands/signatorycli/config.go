package signatorycli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewConfigCommand(conf *RootContextConfig) *cobra.Command {
	cmd := cobra.Command{
		Use:     "config",
		Aliases: []string{"conf"},
		Short:   "signatory-cli configuration commands",
	}
	cmd.AddCommand(newConfigInitCommand(conf))
	cmd.AddCommand(newIDCommand(conf))
	return &cmd
}

func newConfigInitCommand(conf *RootContextConfig) *cobra.Command {
	cmd := cobra.Command{
		Use:   "init",
		Short: "Create new configuration file with provided parameters",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := configFile{
				Endpoint: conf.GetEndpoint(),
				Secure:   conf.Secure,
			}
			buf, err := yaml.Marshal(&c)
			if err != nil {
				return err
			}
			fileName := conf.GetConfigFile()
			dir := filepath.Dir(fileName)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			if err := os.WriteFile(fileName, buf, 0600); err != nil {
				return err
			}
			fmt.Printf("Configuration file %s is successfully created\n", fileName)
			return nil
		},
	}
	return &cmd
}

func newIDCommand(conf *RootContextConfig) *cobra.Command {
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
			priv, err := ed25519.GeneratePrivateKey()
			if err != nil {
				return err
			}
			keyData := priv.COSE().Encode()

			fileName := conf.GetIdentityFile()
			dir := filepath.Dir(fileName)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}

			fd, err := os.OpenFile(fileName, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					fmt.Printf("File %s already exists.\nDo you want to overwrite it? [yes/no] ", fileName)
					var (
						ans string
						n   int
					)
					n, err = fmt.Scan(&ans)
					if err != nil {
						return err
					}
					if n == 1 && strings.EqualFold(ans, "yes") {
						fd, err = os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0600)
					} else {
						return errors.New("terminated by user")
					}
				}
			}
			if err != nil {
				return err
			}
			if _, err := fd.Write(keyData); err != nil {
				return err
			}
			if err := fd.Close(); err != nil {
				return err
			}
			fmt.Printf("Identity key %s is successfully created\n", fileName)
			return nil
		},
	}

	printCmd := cobra.Command{
		Use:     "print",
		Aliases: []string{"p"},
		Short:   "Print the public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, err := conf.LoadIdentity()
			if err != nil {
				return err
			}
			fmt.Println(hex.EncodeToString(priv.Public().COSE().Encode()))
			return nil
		},
	}

	cmd.AddCommand(&genCmd)
	cmd.AddCommand(&printCmd)
	return &cmd
}
