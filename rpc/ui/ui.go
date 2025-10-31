package ui

import (
	"context"
	"errors"
	"fmt"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/ui"
)

type Service struct {
	UI ui.UI
}

type rpcDialog struct {
	Title string     `cbor:"0,keyasint,omitempty"`
	Items []*rpcItem `cbor:"1,keyasint,omitempty"`
}

type rpcItem struct {
	Message      *ui.Message     `cbor:"0,keyasint,omitempty"`
	Fingerprint  *ui.Fingerprint `cbor:"1,keyasint,omitempty"`
	Input        *input          `cbor:"2,keyasint,omitempty"`
	Password     *password       `cbor:"3,keyasint,omitempty"`
	Confirmation *confirmation   `cbor:"4,keyasint,omitempty"`
}

type input struct {
	Prompt string `cbor:"0,keyasint,omitempty"`
}

type password struct {
	Prompt string `cbor:"0,keyasint,omitempty"`
}

type confirmation struct {
	Prompt string `cbor:"0,keyasint,omitempty"`
}

type rpcAPI interface {
	ErrorMessage(ctx context.Context, msg string) error
	Dialog(ctx context.Context, dialog *rpcDialog) (results []any, err error)
}

func (r Service) RegisterSelf(reg rpc.Registrar) {
	var api rpcAPI = r
	reg.RegisterModule("ui", &api)
}

func (r Service) ErrorMessage(ctx context.Context, msg string) error {
	return r.UI.ErrorMessage(ctx, msg)
}

func (r Service) Dialog(ctx context.Context, dialog *rpcDialog) (results []any, err error) {
	d := ui.Dialog{
		Title: dialog.Title,
		Items: make([]ui.Item, 0, len(dialog.Items)),
	}
	results = make([]any, 0, len(dialog.Items))

	for _, item := range dialog.Items {
		switch {
		case item.Message != nil:
			d.Items = append(d.Items, item.Message)

		case item.Fingerprint != nil:
			d.Items = append(d.Items, item.Fingerprint)

		case item.Input != nil:
			value := new(string)
			d.Items = append(d.Items, &ui.Input{
				Prompt: item.Input.Prompt,
				Value:  value,
			})
			results = append(results, value)
		case item.Password != nil:
			value := new(string)
			d.Items = append(d.Items, &ui.Password{
				Prompt: item.Password.Prompt,
				Value:  value,
			})
			results = append(results, value)
		case item.Confirmation != nil:
			value := new(bool)
			d.Items = append(d.Items, &ui.Confirmation{
				Prompt: item.Confirmation.Prompt,
				Value:  value,
			})
			results = append(results, value)
		}
	}
	if err = r.UI.Dialog(ctx, &d); err != nil {
		return nil, err
	}
	return
}

type Proxy struct {
	RPC rpc.Caller
}

func (p Proxy) Dialog(ctx context.Context, dialog *ui.Dialog) error {
	d := rpcDialog{
		Title: dialog.Title,
		Items: make([]*rpcItem, 0, len(dialog.Items)),
	}

	for _, item := range dialog.Items {
		switch item := item.(type) {
		case *ui.Message:
			d.Items = append(d.Items, &rpcItem{Message: item})

		case *ui.Fingerprint:
			d.Items = append(d.Items, &rpcItem{Fingerprint: item})

		case *ui.Input:
			d.Items = append(d.Items, &rpcItem{Input: &input{Prompt: item.Prompt}})

		case *ui.Password:
			d.Items = append(d.Items, &rpcItem{Password: &password{Prompt: item.Prompt}})

		case *ui.Confirmation:
			d.Items = append(d.Items, &rpcItem{Confirmation: &confirmation{Prompt: item.Prompt}})

		default:
			panic(fmt.Sprintf("unexpected ui.Item: %#v", item))
		}
	}

	var results []any
	if err := p.RPC.Call(ctx, &results, "ui", "dialog", &d); err != nil {
		return err
	}

	idx := 0
	for _, item := range dialog.Items {
		switch item := item.(type) {
		case *ui.Input:
			if idx >= len(results) {
				return errors.New("ui: invalid rpc reply")
			}
			if s, ok := results[idx].(string); ok {
				*item.Value = s
			} else {
				return errors.New("ui: invalid rpc reply")
			}
			idx++

		case *ui.Password:
			if idx >= len(results) {
				return errors.New("ui: invalid rpc reply")
			}
			if s, ok := results[idx].(string); ok {
				*item.Value = s
			} else {
				return errors.New("ui: invalid rpc reply")
			}
			idx++

		case *ui.Confirmation:
			if idx >= len(results) {
				return errors.New("ui: invalid rpc reply")
			}
			if s, ok := results[idx].(bool); ok {
				*item.Value = s
			} else {
				return errors.New("ui: invalid rpc reply")
			}
			idx++
		}
	}

	return nil
}

func (p Proxy) ErrorMessage(ctx context.Context, msg string) error {
	return p.RPC.Call(ctx, nil, "ui", "errorMessage", msg)
}

var (
	_ rpc.Module = Service{}
	_ ui.UI      = Proxy{}
)
