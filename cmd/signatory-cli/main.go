package main

import (
	"fmt"
	"os"

	"github.com/signatory-io/signatory-core/commands/signatorycli"
)

func main() {
	cmd := signatorycli.NewRootCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
