package codec

import (
	"encoding/json"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type Codec interface {
	Unmarshal(data []byte, v any) error
	Marshal(v any) ([]byte, error)
	NewStreamDecoder(r io.Reader) StreamDecoder
}

type StreamDecoder interface {
	Decode(v any) error
}

type CBOR struct{}

func (CBOR) Unmarshal(data []byte, v any) error         { return cbor.Unmarshal(data, v) }
func (CBOR) Marshal(v any) ([]byte, error)              { return cbor.Marshal(v) }
func (CBOR) NewStreamDecoder(r io.Reader) StreamDecoder { return cbor.NewDecoder(r) }

type JSON struct{}

func (JSON) Unmarshal(data []byte, v any) error         { return json.Unmarshal(data, v) }
func (JSON) Marshal(v any) ([]byte, error)              { return json.Marshal(v) }
func (JSON) NewStreamDecoder(r io.Reader) StreamDecoder { return json.NewDecoder(r) }
