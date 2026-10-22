package fortivpn

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	protoIPv4 = 0x0021
	protoIPCP = 0x8021
	protoLCP  = 0xc021
)

const (
	codeConfReq   = 1
	codeConfAck   = 2
	codeConfNak   = 3
	codeConfRej   = 4
	codeTermReq   = 5
	codeTermAck   = 6
	codeCodeRej   = 7
	codeProtoRej  = 8
	codeEchoReq   = 9
	codeEchoReply = 10
	codeDiscard   = 11
)

const (
	lcpOptMRU      = 1
	lcpOptACCM     = 2
	lcpOptMagic    = 5
	ipcpOptAddr    = 3
	ipcpOptDNS1    = 129
	ipcpOptDNS2    = 131
	defaultPPPMRU  = 1500
	negotiateRetry = 3 * time.Second
)

var errTerminated = errors.New("gateway terminated the tunnel")

type frameConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

func newFrameConn(conn net.Conn) *frameConn {
	return &frameConn{conn: conn, r: bufio.NewReaderSize(conn, 64*1024)}
}

func (f *frameConn) readFrame() ([]byte, error) {
	var header [6]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return nil, err
	}
	if string(header[:]) == "HTTP/1" {
		line, _ := f.r.ReadString('\n')
		return nil, fmt.Errorf("gateway refused the tunnel (HTTP/1%s); is tunnel mode allowed for this user?", trimLine(line))
	}
	total := binary.BigEndian.Uint16(header[0:2])
	magic := binary.BigEndian.Uint16(header[2:4])
	size := binary.BigEndian.Uint16(header[4:6])
	if magic != 0x5050 || total < 7 || total-6 != size {
		return nil, fmt.Errorf("bad tunnel frame header % x", header)
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(f.r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func (f *frameConn) writeFrame(proto uint16, payload []byte) error {
	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(frame)))
	binary.BigEndian.PutUint16(frame[2:4], 0x5050)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(frame)-6))
	binary.BigEndian.PutUint16(frame[6:8], proto)
	copy(frame[8:], payload)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	_, err := f.conn.Write(frame)
	return err
}

func trimLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

type cpPacket struct {
	code byte
	id   byte
	data []byte
}

func parseCP(b []byte) (cpPacket, bool) {
	if len(b) < 4 {
		return cpPacket{}, false
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 || length > len(b) {
		return cpPacket{}, false
	}
	return cpPacket{code: b[0], id: b[1], data: b[4:length]}, true
}

func (p cpPacket) marshal() []byte {
	b := make([]byte, 4+len(p.data))
	b[0], b[1] = p.code, p.id
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], p.data)
	return b
}

type cpOption struct {
	typ  byte
	data []byte
}

func parseOptions(b []byte) ([]cpOption, bool) {
	var opts []cpOption
	for len(b) > 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return nil, false
		}
		opts = append(opts, cpOption{typ: b[0], data: b[2:b[1]]})
		b = b[b[1]:]
	}
	return opts, true
}

func marshalOptions(opts []cpOption) []byte {
	var b []byte
	for _, o := range opts {
		b = append(b, o.typ, byte(2+len(o.data)))
		b = append(b, o.data...)
	}
	return b
}

type pppLink struct {
	fc *frameConn

	magic    uint32
	lcpID    byte
	lcpMagic bool
	peerMRU  int

	ipcpID   byte
	addr     [4]byte
	dns      [2][4]byte
	wantDNS  [2]bool
	lcpUp    [2]bool
	ipcpUp   [2]bool
	ipcpSent bool

	echoMu    sync.Mutex
	otherID   byte
	lastEcho  time.Time
	echoReply bool
}

type pppResult struct {
	addr netip.Addr
	dns  []netip.Addr
	mtu  int
}

func newPPPLink(fc *frameConn) *pppLink {
	var m [4]byte
	_, _ = rand.Read(m[:])
	return &pppLink{
		fc:       fc,
		magic:    binary.BigEndian.Uint32(m[:]),
		lcpMagic: true,
		peerMRU:  defaultPPPMRU,
		wantDNS:  [2]bool{true, true},
	}
}

func (l *pppLink) negotiate(timeout time.Duration) (pppResult, error) {
	deadline := time.Now().Add(timeout)
	if err := l.sendLCPConfReq(); err != nil {
		return pppResult{}, err
	}
	defer l.fc.conn.SetReadDeadline(time.Time{})

	for !(l.lcpUp[0] && l.lcpUp[1] && l.ipcpUp[0] && l.ipcpUp[1]) {
		if time.Now().After(deadline) {
			return pppResult{}, errors.New("PPP negotiation timed out")
		}
		_ = l.fc.conn.SetReadDeadline(time.Now().Add(negotiateRetry))
		frame, err := l.fc.readFrame()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {

				if !l.lcpUp[1] {
					err = l.sendLCPConfReq()
				} else if l.ipcpSent && !l.ipcpUp[1] {
					err = l.sendIPCPConfReq()
				} else {
					err = nil
				}
				if err != nil {
					return pppResult{}, err
				}
				continue
			}
			return pppResult{}, err
		}
		if err := l.handleFrame(frame, nil); err != nil {
			return pppResult{}, err
		}
		if l.lcpUp[0] && l.lcpUp[1] && !l.ipcpSent {
			if err := l.sendIPCPConfReq(); err != nil {
				return pppResult{}, err
			}
		}
	}

	res := pppResult{addr: netip.AddrFrom4(l.addr), mtu: min(l.peerMRU, defaultPPPMRU)}
	for i, dns := range l.dns {
		if l.wantDNS[i] && dns != [4]byte{} {
			res.dns = append(res.dns, netip.AddrFrom4(dns))
		}
	}
	return res, nil
}

func (l *pppLink) run(deliver func([]byte)) error {
	for {
		frame, err := l.fc.readFrame()
		if err != nil {
			return err
		}
		if err := l.handleFrame(frame, deliver); err != nil {
			return err
		}
	}
}

func (l *pppLink) writeIPv4(pkt []byte) error {
	return l.fc.writeFrame(protoIPv4, pkt)
}

func (l *pppLink) sendEcho(maxSilence time.Duration) (dead bool, err error) {
	l.echoMu.Lock()
	dead = l.echoReply && time.Since(l.lastEcho) > maxSilence
	l.echoMu.Unlock()
	if dead {
		return true, nil
	}
	data := binary.BigEndian.AppendUint32(nil, l.magic)
	return false, l.fc.writeFrame(protoLCP, cpPacket{code: codeEchoReq, id: l.nextOtherID(), data: data}.marshal())
}

func (l *pppLink) nextOtherID() byte {
	l.echoMu.Lock()
	defer l.echoMu.Unlock()
	l.otherID++
	return l.otherID
}

func (l *pppLink) handleFrame(frame []byte, deliver func([]byte)) error {
	if len(frame) < 2 {
		return nil
	}
	proto := binary.BigEndian.Uint16(frame[0:2])
	payload := frame[2:]
	switch proto {
	case protoIPv4:
		if deliver != nil {
			deliver(payload)
		}
		return nil
	case protoLCP:
		return l.handleLCP(payload)
	case protoIPCP:
		return l.handleIPCP(payload)
	default:

		data := append(binary.BigEndian.AppendUint16(nil, proto), payload...)
		if len(data) > 64 {
			data = data[:64]
		}
		return l.fc.writeFrame(protoLCP, cpPacket{code: codeProtoRej, id: l.nextOtherID(), data: data}.marshal())
	}
}

func (l *pppLink) sendLCPConfReq() error {
	var opts []cpOption
	if l.lcpMagic {
		opts = append(opts, cpOption{typ: lcpOptMagic, data: binary.BigEndian.AppendUint32(nil, l.magic)})
	}
	l.lcpID++
	return l.fc.writeFrame(protoLCP, cpPacket{code: codeConfReq, id: l.lcpID, data: marshalOptions(opts)}.marshal())
}

func (l *pppLink) handleLCP(b []byte) error {
	pkt, ok := parseCP(b)
	if !ok {
		return nil
	}
	reply := func(code byte, data []byte) error {
		return l.fc.writeFrame(protoLCP, cpPacket{code: code, id: pkt.id, data: data}.marshal())
	}
	switch pkt.code {
	case codeConfReq:
		opts, ok := parseOptions(pkt.data)
		if !ok {
			return nil
		}
		var rejected []cpOption
		for _, o := range opts {
			switch o.typ {
			case lcpOptMRU:
				if len(o.data) == 2 {
					l.peerMRU = int(binary.BigEndian.Uint16(o.data))
				}
			case lcpOptACCM, lcpOptMagic:
			default:

				rejected = append(rejected, o)
			}
		}
		if len(rejected) > 0 {
			return reply(codeConfRej, marshalOptions(rejected))
		}
		l.lcpUp[0] = true
		return reply(codeConfAck, pkt.data)
	case codeConfAck:
		if pkt.id == l.lcpID {
			l.lcpUp[1] = true
		}
	case codeConfNak:
		if pkt.id == l.lcpID {
			var m [4]byte
			_, _ = rand.Read(m[:])
			l.magic = binary.BigEndian.Uint32(m[:])
			return l.sendLCPConfReq()
		}
	case codeConfRej:
		if pkt.id == l.lcpID {
			l.lcpMagic = false
			return l.sendLCPConfReq()
		}
	case codeTermReq:
		_ = reply(codeTermAck, nil)
		return errTerminated
	case codeTermAck:
		return errTerminated
	case codeEchoReq:
		data := binary.BigEndian.AppendUint32(nil, l.magic)
		if len(pkt.data) > 4 {
			data = append(data, pkt.data[4:]...)
		}
		return reply(codeEchoReply, data)
	case codeEchoReply:
		l.echoMu.Lock()
		l.echoReply = true
		l.lastEcho = time.Now()
		l.echoMu.Unlock()
	case codeCodeRej, codeProtoRej, codeDiscard:
	default:
		return l.fc.writeFrame(protoLCP, cpPacket{code: codeCodeRej, id: l.nextOtherID(), data: b}.marshal())
	}
	return nil
}

func (l *pppLink) sendIPCPConfReq() error {
	opts := []cpOption{{typ: ipcpOptAddr, data: l.addr[:]}}
	for i, typ := range []byte{ipcpOptDNS1, ipcpOptDNS2} {
		if l.wantDNS[i] {
			opts = append(opts, cpOption{typ: typ, data: l.dns[i][:]})
		}
	}
	l.ipcpID++
	l.ipcpSent = true
	return l.fc.writeFrame(protoIPCP, cpPacket{code: codeConfReq, id: l.ipcpID, data: marshalOptions(opts)}.marshal())
}

func (l *pppLink) handleIPCP(b []byte) error {
	pkt, ok := parseCP(b)
	if !ok {
		return nil
	}
	reply := func(code byte, data []byte) error {
		return l.fc.writeFrame(protoIPCP, cpPacket{code: code, id: pkt.id, data: data}.marshal())
	}
	switch pkt.code {
	case codeConfReq:
		opts, ok := parseOptions(pkt.data)
		if !ok {
			return nil
		}
		var rejected []cpOption
		for _, o := range opts {
			if o.typ != ipcpOptAddr {
				rejected = append(rejected, o)
			}
		}
		if len(rejected) > 0 {
			return reply(codeConfRej, marshalOptions(rejected))
		}
		l.ipcpUp[0] = true
		return reply(codeConfAck, pkt.data)
	case codeConfAck:
		if pkt.id == l.ipcpID {
			l.ipcpUp[1] = true
		}
	case codeConfNak, codeConfRej:
		if pkt.id != l.ipcpID {
			return nil
		}
		opts, ok := parseOptions(pkt.data)
		if !ok {
			return nil
		}
		for _, o := range opts {
			switch o.typ {
			case ipcpOptAddr:
				if pkt.code == codeConfRej {
					return errors.New("gateway rejected IP address negotiation")
				}
				copy(l.addr[:], o.data)
			case ipcpOptDNS1, ipcpOptDNS2:
				i := 0
				if o.typ == ipcpOptDNS2 {
					i = 1
				}
				if pkt.code == codeConfRej {
					l.wantDNS[i] = false
				} else {
					copy(l.dns[i][:], o.data)
				}
			}
		}
		return l.sendIPCPConfReq()
	case codeTermReq:
		_ = reply(codeTermAck, nil)
		return errTerminated
	}
	return nil
}
