package vsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ContextAny        = unix.VMADDR_CID_ANY
	ContextHost       = unix.VMADDR_CID_HOST
	ContextHypervisor = unix.VMADDR_CID_HYPERVISOR

	PortAny = unix.VMADDR_PORT_ANY
)

type Conn struct {
	fd     *os.File
	l_addr Addr
	r_addr Addr
}

var _ net.Conn = (*Conn)(nil)

func wrapErr(err error, op string, source, addr net.Addr) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "vsock",
		Source: source,
		Addr:   addr,
		Err:    err,
	}
}

func (c *Conn) wrapErr(err error, op string) *net.OpError {
	return wrapErr(err, op, &c.l_addr, &c.r_addr)
}

func newUnbound() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	return newFD(fd)
}

func newFD(fd int) (*os.File, error) {
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "vsock"), nil
}

type Addr struct {
	CID  uint32
	Port uint32
}

func (*Addr) Network() string {
	return "vsock"
}

func (a *Addr) String() string {
	return fmt.Sprintf("%d:%d", a.CID, a.Port)
}

func (a *Addr) sockaddr() *unix.SockaddrVM {
	return &unix.SockaddrVM{
		CID:  a.CID,
		Port: a.Port,
	}
}

func newConn(fd *os.File, peer unix.Sockaddr) (*Conn, error) {
	raw, err := fd.SyscallConn()
	if err != nil {
		return nil, err
	}
	var sn unix.Sockaddr
	var sysErr error
	if err := raw.Control(func(sysfd uintptr) {
		sn, sysErr = unix.Getsockname(int(sysfd))
	}); err != nil {
		return nil, err
	}
	if sysErr != nil {
		return nil, sysErr
	}
	l_sa := sn.(*unix.SockaddrVM)
	l_addr := Addr{CID: l_sa.CID, Port: l_sa.Port}

	if peer == nil {
		if err := raw.Control(func(sysfd uintptr) {
			peer, sysErr = unix.Getpeername(int(sysfd))
		}); err != nil {
			return nil, err
		}
		if sysErr != nil {
			return nil, sysErr
		}
	}
	r_sa := peer.(*unix.SockaddrVM)
	r_addr := Addr{CID: r_sa.CID, Port: r_sa.Port}

	return &Conn{fd: fd, l_addr: l_addr, r_addr: r_addr}, nil
}

func newConnFromSys(fd int, peer unix.Sockaddr) (*Conn, error) {
	os_fd, err := newFD(fd)
	if err != nil {
		return nil, err
	}
	return newConn(os_fd, peer)
}

func Dial(addr *Addr) (conn *Conn, err error) {
	fd, err := newUnbound()
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	defer func() {
		if err != nil {
			fd.Close()
		}
	}()

	raw, err := fd.SyscallConn()
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}

	var connectErr error
	if err := raw.Control(func(sysfd uintptr) {
		connectErr = unix.Connect(int(sysfd), addr.sockaddr())
	}); err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	switch connectErr {
	case unix.EINPROGRESS:
	case nil:
		return newConn(fd, nil)
	default:
		return nil, wrapErr(connectErr, "dial", nil, addr)
	}

	var pn unix.Sockaddr
	if poll_err := raw.Write(func(sysfd uintptr) bool {
		var val int
		val, err = unix.GetsockoptInt(int(sysfd), unix.SOL_SOCKET, unix.SO_ERROR)
		if err == nil && val != 0 {
			err = unix.Errno(val)
		}
		if err != nil {
			return true
		}
		pn, err = unix.Getpeername(int(sysfd))
		return err == nil || err != unix.ENOTCONN
	}); poll_err != nil {
		return nil, wrapErr(poll_err, "dial", nil, addr)
	}
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	return newConn(fd, pn)
}

func DialContext(ctx context.Context, addr *Addr) (conn *Conn, err error) {
	fd, err := newUnbound()
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	defer func() {
		if err != nil {
			fd.Close()
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		fd.SetDeadline(deadline)
	}

	// Cancel pending I/O when context is done
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			fd.SetDeadline(time.Now())
		case <-done:
		}
	}()

	raw, err := fd.SyscallConn()
	if err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}

	var connectErr error
	if err := raw.Control(func(sysfd uintptr) {
		connectErr = unix.Connect(int(sysfd), addr.sockaddr())
	}); err != nil {
		return nil, wrapErr(err, "dial", nil, addr)
	}
	switch connectErr {
	case unix.EINPROGRESS:
	case nil:
		fd.SetDeadline(time.Time{})
		return newConn(fd, nil)
	default:
		if ctx.Err() != nil {
			return nil, wrapErr(ctx.Err(), "dial", nil, addr)
		}
		return nil, wrapErr(connectErr, "dial", nil, addr)
	}

	var pn unix.Sockaddr
	if poll_err := raw.Write(func(sysfd uintptr) bool {
		var val int
		val, err = unix.GetsockoptInt(int(sysfd), unix.SOL_SOCKET, unix.SO_ERROR)
		if err == nil && val != 0 {
			err = unix.Errno(val)
		}
		if err != nil {
			return true
		}
		pn, err = unix.Getpeername(int(sysfd))
		return err == nil || err != unix.ENOTCONN
	}); poll_err != nil {
		if ctx.Err() != nil {
			return nil, wrapErr(ctx.Err(), "dial", nil, addr)
		}
		return nil, wrapErr(poll_err, "dial", nil, addr)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, wrapErr(ctx.Err(), "dial", nil, addr)
		}
		return nil, wrapErr(err, "dial", nil, addr)
	}
	fd.SetDeadline(time.Time{})
	return newConn(fd, pn)
}

func (conn *Conn) Close() error {
	if err := conn.fd.Close(); err != nil {
		return wrapErr(err, "close", nil, nil)
	}
	return nil
}

func (conn *Conn) Read(b []byte) (n int, err error) {
	n, err = conn.fd.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, conn.wrapErr(err, "read")
	}
	return n, err
}

func (conn *Conn) Write(b []byte) (n int, err error) {
	n, err = conn.fd.Write(b)
	if err != nil {
		return n, conn.wrapErr(err, "write")
	}
	return n, nil
}

func (conn *Conn) LocalAddr() net.Addr {
	return &conn.l_addr
}

func (conn *Conn) RemoteAddr() net.Addr {
	return &conn.r_addr
}

func (conn *Conn) SetDeadline(t time.Time) error {
	if err := conn.fd.SetDeadline(t); err != nil {
		return wrapErr(err, "set", nil, nil)
	}
	return nil
}

func (conn *Conn) SetReadDeadline(t time.Time) error {
	if err := conn.fd.SetReadDeadline(t); err != nil {
		return wrapErr(err, "set", nil, nil)
	}
	return nil
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	if err := conn.fd.SetWriteDeadline(t); err != nil {
		return wrapErr(err, "set", nil, nil)
	}
	return nil
}

type Listener struct {
	fd     *os.File
	raw    syscall.RawConn
	l_addr Addr
}

var _ net.Listener = (*Listener)(nil)

func Listen(addr *Addr) (listener *Listener, err error) {
	fd, err := newUnbound()
	if err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	defer func() {
		if err != nil {
			fd.Close()
		}
	}()
	raw, err := fd.SyscallConn()
	if err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}

	var sysErr error
	if err := raw.Control(func(sysfd uintptr) {
		sysErr = unix.Bind(int(sysfd), addr.sockaddr())
	}); err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	if sysErr != nil {
		return nil, wrapErr(sysErr, "listen", addr, nil)
	}

	var sn unix.Sockaddr
	if err := raw.Control(func(sysfd uintptr) {
		sn, sysErr = unix.Getsockname(int(sysfd))
	}); err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	if sysErr != nil {
		return nil, wrapErr(sysErr, "listen", addr, nil)
	}
	l_sa := sn.(*unix.SockaddrVM)
	l_addr := Addr{CID: l_sa.CID, Port: l_sa.Port}

	if err := raw.Control(func(sysfd uintptr) {
		sysErr = unix.Listen(int(sysfd), unix.SOMAXCONN)
	}); err != nil {
		return nil, wrapErr(err, "listen", addr, nil)
	}
	if sysErr != nil {
		return nil, wrapErr(sysErr, "listen", addr, nil)
	}
	return &Listener{fd: fd, raw: raw, l_addr: l_addr}, nil
}

func (l *Listener) Close() error {
	if err := l.fd.Close(); err != nil {
		return wrapErr(err, "close", nil, nil)
	}
	return nil
}

func (l *Listener) AcceptVSock() (conn *Conn, err error) {
	var nfd int
	var sa unix.Sockaddr
	l.raw.Control(func(sysfd uintptr) {
		nfd, sa, err = unix.Accept(int(sysfd))
	})
	switch err {
	case unix.EAGAIN:
	case nil:
		return newConnFromSys(nfd, sa)
	default:
		return nil, wrapErr(err, "accept", &l.l_addr, nil)
	}

	if poll_err := l.raw.Read(func(sysfd uintptr) bool {
		nfd, sa, err = unix.Accept(int(sysfd))
		return err == nil || err != unix.EAGAIN
	}); poll_err != nil {
		return nil, wrapErr(poll_err, "accept", &l.l_addr, nil)
	}
	if err != nil {
		return nil, wrapErr(err, "accept", &l.l_addr, nil)
	}

	return newConnFromSys(nfd, sa)
}

func (l *Listener) Accept() (conn net.Conn, err error) {
	return l.AcceptVSock()
}

func (l *Listener) Addr() net.Addr {
	return &l.l_addr
}
