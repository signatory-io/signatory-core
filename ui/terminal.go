package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/signatory-io/signatory-core/crypto/utils"
	"golang.org/x/term"
)

type Terminal struct {
	mtx sync.Mutex
}

var aLongTimeAgo = time.Unix(1, 0)

func readCtx(ctx context.Context, r *os.File, readFunc func() (string, error)) (string, error) {
	ctxErr := make(chan error)
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			r.SetDeadline(aLongTimeAgo)
			ctxErr <- ctx.Err()
		case <-done:
			ctxErr <- nil
		}
	}()

	line, err := readFunc()
	close(done)
	if e := <-ctxErr; e != nil {
		err = e
	}
	r.SetDeadline(time.Time{})

	if errors.Is(err, io.EOF) {
		err = ErrCancelled
	}
	return line, err
}

func (t *Terminal) Dialog(ctx context.Context, dialog *Dialog) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("standard input is not a terminal")
	}
	t.mtx.Lock()
	defer t.mtx.Unlock()

	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), state)

	stdin := stdinPipe()
	tr := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{stdin, os.Stdout}, "")

	fmt.Fprintln(tr, "")
	if dialog.Title != "" {
		fmt.Fprintf(tr, "# %s\n", dialog.Title)
	}
	for _, item := range dialog.Items {
		switch item := item.(type) {
		case *Message:
			if item.Label != "" {
				if strings.ContainsRune(item.Message, '\n') {
					// multi line message
					fmt.Fprintf(tr, "%s:\n", item.Label)
				} else {
					fmt.Fprintf(tr, "%s: ", item.Label)
				}
			}
			fmt.Fprintln(tr, item.Message)

		case *Fingerprint:
			if item.Label != "" {
				fmt.Fprintf(tr, "%s:\n", item.Label)
			}
			tr.Write(utils.FingerprintRandomArt(item.Header, item.Fingerprint))

		case *Input:
			tr.SetPrompt(item.Prompt + ": ")
			v, err := readCtx(ctx, stdin, tr.ReadLine)
			if err != nil {
				return err
			}
			*item.Value = string(v)

		case *Password:
			v, err := readCtx(ctx, stdin, func() (string, error) { return tr.ReadPassword(item.Prompt + ": ") })
			if err != nil {
				return err
			}
			*item.Value = string(v)

		case *Confirmation:
			tr.SetPrompt(item.Prompt + " [yes/No]: ")
			v, err := readCtx(ctx, stdin, tr.ReadLine)
			if err != nil {
				return err
			}
			*item.Value = strings.EqualFold(string(v), "yes")

		default:
			panic(fmt.Sprintf("unexpected ui.Item: %#v", item))
		}
	}
	return nil
}

func (t *Terminal) ErrorMessage(ctx context.Context, msg string) error {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	fmt.Printf("Error: %s", msg)
	return nil
}

var stdinPipe = sync.OnceValue(func() *os.File {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	go io.Copy(w, os.Stdin)
	return r
})

var _ UI = (*Terminal)(nil)
