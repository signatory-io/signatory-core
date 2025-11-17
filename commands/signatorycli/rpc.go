package signatorycli

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/pkcs8"
	cryptoutils "github.com/signatory-io/signatory-core/crypto/utils"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/cbor"
	"github.com/signatory-io/signatory-core/rpc/rpcutils"
	rpcui "github.com/signatory-io/signatory-core/rpc/ui"
	"github.com/signatory-io/signatory-core/signer/api"
	"github.com/signatory-io/signatory-core/ui"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/spf13/cobra"
)

func (r *Config) NewRPC(ctx context.Context) (rpcutils.CallerCloser, error) {
	var termUI ui.Terminal
	uiSvc := rpcui.Service{
		UI: &termUI,
	}
	handler := rpc.NewHandler()
	handler.RegisterModule(rpcui.Path, uiSvc)
	return rpcutils.NewRPCClient[cbor.Layout](ctx, r.RPCEndpoint, handler, r)
}

func newVaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "vault",
		Short: "Vault operations",
	}
	cmd.AddCommand(newListVaultsCommand())
	return &cmd
}

func newListVaultsCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "list",
		Aliases: []string{"l"},
		Short:   "List vaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			var conf Config
			conf.Default()
			if err := conf.FromCmdline(true, cmd.Flags()); err != nil {
				return err
			}
			r, err := conf.NewRPC(cmd.Context())
			if err != nil {
				return err
			}
			defer r.Close()

			var vaults []api.VaultInfo
			if err = r.Call(cmd.Context(), &vaults, "signer", "listVaults"); err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			fmt.Fprintln(w, "ID\tType\tInstance Info")
			for _, v := range vaults {
				fmt.Fprintf(w, "%s\t%s\t%s\n", v.ID, v.Name, v.InstanceInfo)
			}
			w.Flush()
			return nil
		},
	}

	return &cmd
}

func newKeyCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "key",
		Short: "Keys operations",
	}
	cmd.AddCommand(newListKeysCommand())
	cmd.AddCommand(newImportKeyCommand())
	cmd.AddCommand(newGenerateKeyCommand())
	cmd.AddCommand(newUnlockCommand())
	cmd.AddCommand(newListAlgsCommand())
	return &cmd
}

func newListKeysCommand() *cobra.Command {
	var (
		vaultID  string
		algNames []string
	)

	cmd := cobra.Command{
		Use:     "list",
		Aliases: []string{"l"},
		Short:   "List keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			var algs []crypto.Algorithm
			if len(algNames) != 0 {
				algs = make([]crypto.Algorithm, len(algNames))
				for i, a := range algNames {
					if algs[i] = crypto.AlgorithmFromString(a); algs[i] == 0 {
						return fmt.Errorf("unknown algorithm %s", a)
					}
				}
			}
			var conf Config
			conf.Default()
			if err := conf.FromCmdline(true, cmd.Flags()); err != nil {
				return err
			}
			r, err := conf.NewRPC(cmd.Context())
			if err != nil {
				return err
			}
			defer r.Close()

			var keys []*api.KeyInfo
			if err = r.Call(cmd.Context(), &keys, "signer", "listKeys", vaultID, algs); err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			fmt.Fprintln(w, "Public Key Hash\tAlgorithm\tVault ID\tVault Instance\tIs Locked")
			for _, k := range keys {
				var locked string
				if k.Locked {
					locked = "*"
				}
				fmt.Fprintf(w, "%v\t%v\t%s\t%s\t%s\n", k.PublicKeyHash, k.Algorithm, k.Vault.ID, k.Vault.InstanceInfo, locked)
			}
			w.Flush()
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&vaultID, "vault", "v", "", "Filter by vault ID")
	f.StringSliceVarP(&algNames, "alg", "a", nil, "Filter by algorithm(s)")

	return &cmd
}

func newGenerateKeyCommand() *cobra.Command {
	var (
		vaultID string
		algName string
		encrypt bool
	)

	cmd := cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate new key",
		RunE: func(cmd *cobra.Command, args []string) error {
			alg := crypto.AlgorithmFromString(algName)
			if alg == 0 {
				return fmt.Errorf("unknown algorithm %s", algName)
			}

			var conf Config
			conf.Default()
			if err := conf.FromCmdline(true, cmd.Flags()); err != nil {
				return err
			}
			r, err := conf.NewRPC(cmd.Context())
			if err != nil {
				return err
			}
			defer r.Close()

			var result api.KeyInfo
			if err = r.Call(cmd.Context(), &result, "signer", "generateKey", vaultID, alg, vault.EncryptKey(encrypt)); err != nil {
				return err
			}
			dumpKeyInfo(&result)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&vaultID, "vault", "v", "", "Vault ID")
	f.StringVarP(&algName, "alg", "a", "", "Algorithm")
	f.BoolVarP(&encrypt, "encrypt", "E", false, "Encrypt key with a password")

	cmd.MarkFlagRequired("alg")

	return &cmd
}

func newImportKeyCommand() *cobra.Command {
	var (
		vaultID string
		format  string
		encrypt bool
		path    string
	)

	cmd := cobra.Command{
		Use:   "import [KEY_DATA]",
		Short: "Import private key",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var keyData []byte
			if len(args) != 0 {
				keyData = []byte(args[0])
			} else {
				if keyData, err = os.ReadFile(path); err != nil {
					return err
				}
			}
			var priv crypto.LocalSigner
			switch format {
			case "erc2335":
				if priv, err = cryptoutils.ParseERC2335Key(keyData); err != nil {
					return err
				}
			case "geth":
				if priv, err = cryptoutils.ParseGethKey(keyData); err != nil {
					return err
				}
			case "tz":
				if priv, err = cryptoutils.ParseTezosPrivateKey(keyData); err != nil {
					return err
				}
			case "pkcs8":
				p, _ := pem.Decode(keyData)
				if p == nil {
					return errors.New("failed to parse PEM block")
				}
				if priv, err = pkcs8.ParsePrivateKey(p.Bytes); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown key format %s", format)
			}

			var conf Config
			conf.Default()
			if err := conf.FromCmdline(true, cmd.Flags()); err != nil {
				return err
			}
			r, err := conf.NewRPC(cmd.Context())
			if err != nil {
				return err
			}
			defer r.Close()

			var result api.KeyInfo
			if err = r.Call(cmd.Context(), &result, "signer", "importKey", vaultID, priv.COSE(), vault.EncryptKey(encrypt)); err != nil {
				return err
			}
			dumpKeyInfo(&result)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&vaultID, "vault", "v", "", "Vault ID")
	f.StringVarP(&format, "format", "f", "pkcs8", "Private key format [pkcs8, geth, tz, erc2335]")
	f.StringVarP(&path, "input", "i", "", "Input file")
	f.BoolVarP(&encrypt, "encrypt", "E", false, "Encrypt key with a password")
	cmd.MarkFlagFilename("input")

	return &cmd
}

func dumpKeyInfo(key *api.KeyInfo) {
	var locked string
	if key.Locked {
		locked = "Yes"
	} else {
		locked = "No"
	}
	ra := cryptoutils.FingerprintRandomArt("", key.PublicKeyHash[:])
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	for i, l := range strings.Split(string(ra), "\n") {
		if l != "" {
			if i == 0 {
				fmt.Fprint(w, "Key's Visualizer:")
			}
			fmt.Fprintf(w, "\t%s\n", l)
		}
	}
	fmt.Fprintf(w, "Public Key Hash:\t%v\n", key.PublicKeyHash)
	fmt.Fprintf(w, "Algorithm:\t%v\n", key.Algorithm)
	fmt.Fprintf(w, "Vault ID:\t%s\n", key.Vault.ID)
	fmt.Fprintf(w, "Vault Instance:\t%s\n", key.Vault.InstanceInfo)
	fmt.Fprintf(w, "Locked:\t%s\n", locked)
	w.Flush()
}

func newUnlockCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "unlock PUBLIC_KEY_HASH",
		Short: "Unlock a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := hex.DecodeString(args[0])
			if err != nil {
				return err
			}
			var pkh crypto.PublicKeyHash
			if len(v) != len(pkh) {
				return errors.New("invalid public key hash length")
			}
			copy(pkh[:], v)

			var conf Config
			conf.Default()
			if err := conf.FromCmdline(true, cmd.Flags()); err != nil {
				return err
			}
			r, err := conf.NewRPC(cmd.Context())
			if err != nil {
				return err
			}
			defer r.Close()
			return r.Call(cmd.Context(), nil, "signer", "unlockKey", &pkh)
		},
	}
	return &cmd
}

func newListAlgsCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "list-algorithms",
		Aliases: []string{"algs"},
		Short:   "List known algorithm IDs",
		Run: func(cmd *cobra.Command, args []string) {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			fmt.Fprintln(w, "ID\tDescription")
			for x := range crypto.NumAlgorithms {
				a := crypto.Algorithm(x + 1)
				fmt.Fprintf(w, "%s\t%s\n", a.Short(), a.String())
			}
			w.Flush()
		},
	}
	return &cmd
}
