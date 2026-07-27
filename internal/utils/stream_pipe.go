package utils

import (
	"io"
	"sync"
	"time"
)

type Stream interface {
	io.Reader
	WriterCloser
}

type WriterCloser interface {
	io.Writer
	CloseWrite() error
}

type nopCloseWriterAdapter struct {
	io.ReadWriter
}

func NopCloseWriterAdapter(stream io.ReadWriter) Stream {
	return &nopCloseWriterAdapter{ReadWriter: stream}
}

func (n *nopCloseWriterAdapter) CloseWrite() error {
	return nil
}

func Pipe(tunnelConn, originConn io.ReadWriter) {
	_ = PipeBidirectional(NopCloseWriterAdapter(tunnelConn), NopCloseWriterAdapter(originConn), 0)
}

func PipeBidirectional(downstream, upstream Stream, maxWaitForSecondStream time.Duration) error {
	done := make(chan struct{}, 2)

	go copyOneWay(downstream, upstream, done)
	go copyOneWay(upstream, downstream, done)

	<-done
	if maxWaitForSecondStream <= 0 {
		return nil
	}

	timer := time.NewTimer(maxWaitForSecondStream)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
	}
	return nil
}

func copyOneWay(dst WriterCloser, src io.Reader, done chan<- struct{}) {
	defer func() {
		_ = dst.CloseWrite()
		done <- struct{}{}
	}()

	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	_, _ = io.CopyBuffer(dst, src, buf)
}

var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
}
