package codec

import (
	"encoding/json"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type Codec[T StreamDecoder] interface {
	Unmarshal(data []byte, v any) error
	Marshal(v any) ([]byte, error)
	NewStreamDecoder(r io.Reader) T
}

type StreamDecoder interface {
	Decode(v any) error
}

type CBOR struct{}
type CBORDecoder = cbor.Decoder

func (CBOR) Unmarshal(data []byte, v any) error        { return cbor.Unmarshal(data, v) }
func (CBOR) Marshal(v any) ([]byte, error)             { return cbor.Marshal(v) }
func (CBOR) NewStreamDecoder(r io.Reader) *CBORDecoder { return cbor.NewDecoder(r) }

type JSON struct{}
type JSONDecoder = json.Decoder

func (JSON) Unmarshal(data []byte, v any) error        { return json.Unmarshal(data, v) }
func (JSON) Marshal(v any) ([]byte, error)             { return json.Marshal(v) }
func (JSON) NewStreamDecoder(r io.Reader) *JSONDecoder { return json.NewDecoder(r) }
