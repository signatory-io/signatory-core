package ui

import (
	"context"
	"errors"
)

type Item interface {
	DialogItem()
}

type Message struct {
	Label   string `cbor:"0,keyasint,omitempty"`
	Message string `cbor:"1,keyasint,omitempty"`
}

func (*Message) DialogItem() {}

type Fingerprint struct {
	Label       string `cbor:"0,keyasint,omitempty"`
	Header      string `cbor:"1,keyasint,omitempty"`
	Fingerprint []byte `cbor:"2,keyasint,omitempty"`
}

func (*Fingerprint) DialogItem() {}

type Input struct {
	Prompt string
	Value  *string
}

func (*Input) DialogItem() {}

type Password struct {
	Prompt string
	Value  *string
}

func (*Password) DialogItem() {}

type Confirmation struct {
	Prompt string
	Value  *bool
}

func (*Confirmation) DialogItem() {}

type Dialog struct {
	Title string
	Items []Item
}

var ErrCancelled = errors.New("cancelled")

type UI interface {
	Dialog(ctx context.Context, dialog *Dialog) error
	ErrorMessage(ctx context.Context, msg string) error
}
