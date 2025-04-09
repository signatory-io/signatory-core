package ui

import (
	"context"
	"errors"
)

type Item interface {
	DialogItem()
}

type Message struct {
	Label   string
	Message string
}

func (*Message) DialogItem() {}

type Fingerprint struct {
	Label       string
	Header      string
	Fingerprint []byte
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
