package preamble

import (
	// Install all backends
	_ "github.com/signatory-io/signatory-core/vault/awskms"
	_ "github.com/signatory-io/signatory-core/vault/local"
)
