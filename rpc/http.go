package rpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

// HTTPHandler implements http.Handler for unidirectional HTTP RPC transport
type HTTPHandler[L Layout[C, M], C codec.Codec, M Message[C]] struct {
	h *Handler
}

func NewHTTPHandler[L Layout[C, M], C codec.Codec, M Message[C]](h *Handler) *HTTPHandler[L, C, M] {
	return &HTTPHandler[L, C, M]{
		h: h,
	}
}

func (h *HTTPHandler[L, C, M]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var (
		codec C
		msg   M
	)
	if err := codec.Unmarshal(body, &msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !msg.IsValid() {
		http.Error(w, "invalid message format", http.StatusBadRequest)
		return
	}

	req := msg.GetRequest()
	if req == nil {
		http.Error(w, "request expected", http.StatusBadRequest)
		return
	}

	id := msg.GetID()
	res, err := handleCall[C](h.h, r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var layout L
	responseMsg := layout.NewResponse(id, res)
	buf, err := codec.Marshal(&responseMsg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", codec.MediaType())
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}

// HTTPHandler is used to make unidirectional RPC calls over HTTP
type HTTPClient[L Layout[C, M], C codec.Codec, M Message[C]] struct {
	c     *http.Client
	url   string
	msgID atomic.Uint64
}

func NewHTTPClient[L Layout[C, M], C codec.Codec, M Message[C]](url string, client *http.Client) *HTTPClient[L, C, M] {
	return &HTTPClient[L, C, M]{
		c:   client,
		url: url,
	}
}

func (h *HTTPClient[L, C, M]) client() *http.Client {
	if h.c != nil {
		return h.c
	}
	return http.DefaultClient
}

type HTTPError struct {
	Code   int
	Header http.Header
	Body   []byte
}

func (h *HTTPError) Error() string {
	return http.StatusText(h.Code)
}

func (h *HTTPClient[L, C, M]) Call(ctx context.Context, result any, objPath, method string, args ...any) (err error) {
	params := make([][]byte, len(args))
	var codec C
	for i, arg := range args {
		if params[i], err = codec.Marshal(arg); err != nil {
			return err
		}
	}
	req := Request{
		Path:       strings.Split(objPath, "/"),
		Method:     method,
		Parameters: params,
	}

	var layout L
	id := h.msgID.Add(1)
	callMsg := layout.NewRequest(id, &req)
	reqBody, err := codec.Marshal(&callMsg)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Accept", codec.MediaType())

	res, err := h.client().Do(httpReq)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return &HTTPError{
			Code:   res.StatusCode,
			Header: res.Header,
			Body:   body,
		}
	}
	var msg M
	if err := codec.Unmarshal(body, &msg); err != nil {
		return err
	}
	if msg.GetID() != id {
		return fmt.Errorf("unexpected message ID: wanted %d, got %d", id, msg.GetID())
	}

	response := msg.GetResponse()
	if response == nil {
		return errors.New("invalid response message")
	}
	if response.Result != nil && result != nil {
		return codec.Unmarshal(response.Result, result)
	}
	return nil
}
