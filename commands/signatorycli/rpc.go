package signatorycli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/utils"
	"github.com/signatory-io/signatory-core/rpc"
	plainconn "github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/secureconn"
	signatoryrpc "github.com/signatory-io/signatory-core/rpc/signatory"
	rpctypes "github.com/signatory-io/signatory-core/rpc/types"
	rpcui "github.com/signatory-io/signatory-core/rpc/ui"
	"github.com/signatory-io/signatory-core/ui"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/spf13/cobra"
)

func (r *RootContext) NewRPC() (*rpc.RPC, error) {
	tcpConn, err := net.Dial("tcp", r.Endpoint)
	if err != nil {
		return nil, err
	}
	var conn rpctypes.EncodedConn
	if r.Identity != nil {
		if conn, err = secureconn.New(tcpConn, r.Identity, nil); err != nil {
			return nil, err
		}
	} else {
		conn = plainconn.New(tcpConn)
	}

	var termUI ui.Terminal
	uiSvc := rpcui.Service{
		UI: &termUI,
	}
	handler := rpc.NewHandler()
	handler.Register(uiSvc)

	return rpc.New(conn, handler), nil
}

func NewVaultCommand(conf *RootContextConfig) *cobra.Command {
	cmd := cobra.Command{
		Use:   "vault",
		Short: "Vault operations",
	}
	cmd.AddCommand(newListVaultsCommand(conf))
	return &cmd
}

func newListVaultsCommand(conf *RootContextConfig) *cobra.Command {
	cmd := cobra.Command{
		Use:     "list",
		Aliases: []string{"l"},
		Short:   "List vaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := conf.NewContext()
			if err != nil {
				return err
			}
			r, err := ctx.NewRPC()
			if err != nil {
				return err
			}
			defer r.Close()

			var vaults []signatoryrpc.VaultInfo
			if err = r.Call(cmd.Context(), &vaults, "sig", "listVaults"); err != nil {
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

func NewKeyCommand(conf *RootContextConfig) *cobra.Command {
	cmd := cobra.Command{
		Use:   "key",
		Short: "Keys operations",
	}
	cmd.AddCommand(newListKeysCommand(conf))
	cmd.AddCommand(newGenerateKeyCommand(conf))
	cmd.AddCommand(newUnlockCommand(conf))
	cmd.AddCommand(newListAlgsCommand())
	return &cmd
}

func newListKeysCommand(conf *RootContextConfig) *cobra.Command {
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

			ctx, err := conf.NewContext()
			if err != nil {
				return err
			}
			r, err := ctx.NewRPC()
			if err != nil {
				return err
			}
			defer r.Close()

			var keys []*signatoryrpc.KeyInfo
			if err = r.Call(cmd.Context(), &keys, "sig", "listKeys", vaultID, algs); err != nil {
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

func newGenerateKeyCommand(conf *RootContextConfig) *cobra.Command {
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

			ctx, err := conf.NewContext()
			if err != nil {
				return err
			}
			r, err := ctx.NewRPC()
			if err != nil {
				return err
			}
			defer r.Close()

			var key signatoryrpc.KeyInfo
			if err = r.Call(cmd.Context(), &key, "sig", "generateKey", vaultID, alg, vault.EncryptKey(encrypt)); err != nil {
				return err
			}

			var locked string
			if key.Locked {
				locked = "Yes"
			} else {
				locked = "No"
			}
			ra := utils.FingerprintRandomArt("", key.PublicKeyHash[:])
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
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&vaultID, "vault", "v", "", "Vault ID")
	f.StringVarP(&algName, "alg", "a", "", "Algorithm")
	f.BoolVarP(&encrypt, "encrypt", "E", false, "Encrypt key with a password")

	cmd.MarkFlagRequired("vault")
	cmd.MarkFlagRequired("alg")

	return &cmd
}

func newUnlockCommand(conf *RootContextConfig) *cobra.Command {
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

			ctx, err := conf.NewContext()
			if err != nil {
				return err
			}
			r, err := ctx.NewRPC()
			if err != nil {
				return err
			}
			defer r.Close()
			return r.Call(cmd.Context(), nil, "sig", "unlockKey", &pkh)
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
