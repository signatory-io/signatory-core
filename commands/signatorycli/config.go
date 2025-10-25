package signatorycli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/signer/api"
	"github.com/signatory-io/signatory-core/utils"
	"github.com/spf13/cobra"
)

func newConfigCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "config",
		Aliases: []string{"conf"},
		Short:   "signatory-cli configuration commands",
	}
	cmd.AddCommand(newConfigInitCommand())
	cmd.AddCommand(newIDCommand())
	return &cmd
}

func newConfigInitCommand() *cobra.Command {
	var (
		secure      bool
		genIdentity bool
	)

	cmd := cobra.Command{
		Use:   "init",
		Short: "Create new configuration file with provided parameters",
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			baseDir, err := f.GetString("base-dir")
			if err != nil {
				panic(err)
			}
			var conf Config

			if f.Changed("base-dir") {
				conf.BasePath = baseDir
			}
			if f.Changed("rpc-address") {
				rpcAddr, err := f.GetString("rpc-address")
				if err != nil {
					panic(err)
				}
				conf.RPCEndpoint = rpcAddr
			} else if secure {
				conf.RPCEndpoint = fmt.Sprintf("secure://%s:%d#%s", defaultHost, api.DefaultSecurePort, defaultIdentityFile)
			} else {
				conf.RPCEndpoint = fmt.Sprintf("tcp://%s:%d", defaultHost, api.DefaultPort)
			}

			u, err := url.Parse(conf.RPCEndpoint)
			if err != nil {
				return nil
			}

			if u.Scheme == "secure" {
				if u.Fragment == "" {
					// add default RPC identity file
					u.Fragment = defaultIdentityFile
					conf.RPCEndpoint = u.String()
				}
			}
			buf, err := yaml.Marshal(&conf)
			if err != nil {
				return err
			}

			confPath, err := f.GetString("config-file")
			if err != nil {
				panic(err)
			}
			confPath = getPath(confPath, baseDir)

			dir := filepath.Dir(confPath)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			if err := os.WriteFile(confPath, buf, 0600); err != nil {
				return err
			}
			fmt.Printf("Configuration file %s is successfully created\n", confPath)

			if u.Scheme == "secure" && genIdentity {
				return genKey(getPath(u.Fragment, baseDir))
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&secure, "secure-connection", "s", false, fmt.Sprintf("Set the default endpoint address to `secure://%s:%d#%s'. Does nothing if the endpoint is explicitly specified", defaultHost, api.DefaultSecurePort, defaultIdentityFile))
	f.BoolVarP(&genIdentity, "gen-identity", "i", true, "Generate a new identity file if secure connection is requested")

	return &cmd
}

func genKey(path string) error {
	priv, err := ed25519.GeneratePrivateKey()
	if err != nil {
		return err
	}
	keyData := priv.COSE().Encode()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	fd, err := os.OpenFile(path, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Printf("File %s already exists.\nDo you want to overwrite it? [yes/no] ", path)
			var (
				ans string
				n   int
			)
			n, err = fmt.Scan(&ans)
			if err != nil {
				return err
			}
			if n == 1 && strings.EqualFold(ans, "yes") {
				fd, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
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
	fmt.Printf("Identity key %s is successfully created\n", path)
	return nil
}

func newIDCommand() *cobra.Command {
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
			return genKey(getPath(keyFile, baseDir))
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
			priv, err := utils.LoadIdentity(getPath(keyFile, baseDir))
			if err != nil {
				return err
			}
			fmt.Println(hex.EncodeToString(priv.Public().COSE().Encode()))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&keyFile, "identity-key", "i", defaultIdentityFile, "Identity key file")

	cmd.AddCommand(&genCmd)
	cmd.AddCommand(&printCmd)
	return &cmd
}
