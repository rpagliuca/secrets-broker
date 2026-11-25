package broker

import (
	"bytes"
	"errors"
	"io"
)

var errLeak = errors.New("upstream response contains the credential")

// leakGuard wraps a response body and stops the stream if the credential
// shows up in it (a service that echoes request headers, for instance).
//
// It holds back the last len(longest needle)-1 bytes until more data
// arrives, so a credential split across two reads is still caught before any
// part of it is released.
type leakGuard struct {
	src     io.ReadCloser
	needles [][]byte
	hold    int
	buf     []byte
	scratch []byte
	err     error
	onLeak  func()
}

func newLeakGuard(src io.ReadCloser, needles [][]byte, onLeak func()) *leakGuard {
	hold := 0
	for _, n := range needles {
		hold = max(hold, len(n)-1)
	}
	return &leakGuard{src: src, needles: needles, hold: hold, scratch: make([]byte, 32<<10), onLeak: onLeak}
}

func (g *leakGuard) Read(p []byte) (int, error) {
	for {
		ready := len(g.buf) - g.hold
		if g.err != nil && g.err != errLeak {
			ready = len(g.buf) // source is finished: everything was scanned
		}
		if ready > 0 {
			n := copy(p, g.buf[:ready])
			g.buf = g.buf[n:]
			return n, nil
		}
		if g.err != nil {
			return 0, g.err
		}
		n, err := g.src.Read(g.scratch)
		g.buf = append(g.buf, g.scratch[:n]...)
		if containsAny(g.buf, g.needles) {
			g.buf, g.err = nil, errLeak
			g.onLeak()
			return 0, errLeak
		}
		if err != nil {
			g.err = err
		}
	}
}

func (g *leakGuard) Close() error { return g.src.Close() }

func containsAny(b []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(b, n) {
			return true
		}
	}
	return false
}
