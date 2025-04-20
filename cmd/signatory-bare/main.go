package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn"
	signatoryrpc "github.com/signatory-io/signatory-core/rpc/signatory"
	"github.com/signatory-io/signatory-core/signatory"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/signatory-io/signatory-core/vault/local"
)

const storeDir = ".signatory/key_store"

func main() {
	home, _ := os.UserHomeDir()
	v, err := local.New(filepath.Join(home, storeDir))
	if err != nil {
		log.Fatal(err)
	}
	sig := signatory.New(map[string]vault.Vault{"local": v})
	svc := signatoryrpc.Service{Signatory: sig}

	handler := rpc.NewHandler()
	handler.Register(&svc)

	tcpListener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", signatoryrpc.DefaultPort))
	if err != nil {
		log.Fatal(err)
	}

	listener := conn.Listener{Listener: tcpListener}
	srv := rpc.Server{Handler: handler}
	log.Fatal(srv.Serve(&listener))
}
