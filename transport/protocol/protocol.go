package protocol

// import (
// 	"github.com/signatory-io/signatory-core/transport/codec"
// 	"github.com/signatory-io/signatory-core/transport/conn"
// )

// type Protocol[C codec.Codec, T conn.Conn] interface {
// 	ReadMessage(conn T, v *Message[C]) error
// 	WriteMessage(conn T, v *Message[C]) error
// 	GetMessage() *Message[C]
// }

// type HTTP[C codec.Codec, T conn.Conn] struct{}

// func (HTTP[C, T]) ReadMessage(conn T, v *Message[C]) error {
// 	return nil
// }

// func (HTTP[C, T]) WriteMessage(conn T, v *Message[C]) error {
// 	return nil
// }

// func (HTTP[C, T]) GetMessage() *Message[C] {
// 	var m Message[C]
// 	return &m
// }

// type RPC[C codec.Codec, T conn.Conn] struct{}

// func (RPC[C, T]) ReadMessage(conn T, v *Message[C]) error {
// 	var m Message[C]
// 	return nil
// }

// func (RPC[C, T]) WriteMessage(conn T, v *Message[C]) error {
// 	var codec C
// 	buf, err := codec.Marshal(v)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = conn.Write(buf)
// 	return err
// }

// func (RPC[C, T]) GetMessage() *Message[C] {
// 	var m Message[C]
// 	return &m
// }
