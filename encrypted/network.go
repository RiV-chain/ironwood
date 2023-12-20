package encrypted

import (
	"crypto/ed25519"

	"github.com/Arceliar/ironwood/types"
	"github.com/Arceliar/phony"
)

const netBufferSize = 128 * 1024

type netManager struct {
	phony.Inbox
	pc      *PacketConn
	reader  phony.Inbox
	readCh  chan netReadInfo
	closed  chan struct{}
	running bool
}

type netReadInfo struct {
	from types.Domain
	data []byte
	err  error
}

func (m *netManager) init(pc *PacketConn) {
	m.pc = pc
	m.readCh = make(chan netReadInfo, 1)
	m.closed = make(chan struct{})
}

func (m *netManager) recv(from *sessionInfo, data []byte) {
	m.reader.Act(from, func() {
		select {
		case m.readCh <- netReadInfo{from: from.domain, data: data}:
		case <-m.closed:
		}
	})
}

func (m *netManager) read() {
	m.Act(nil, func() {
		if m.running {
			return
		}
		m.running = true
		buf := make([]byte, netBufferSize)
		var rl func()
		rl = func() {
			n, from, err := m.pc.PacketConn.ReadFrom(buf)
			if err != nil {
				// Exit the loop
				m.running = false
				if m.pc.IsClosed() {
					select {
					case <-m.closed:
					default:
						close(m.closed)
					}
				}
				// FIXME we need something better here
				//  A read deadline could return an error
				//  That would get passed to the next read call
				//  This would happen even if the reader resets the deadline before calling ReadFrom
				select {
				case m.readCh <- netReadInfo{err: err}:
				default:
				}
			} else {
				msg := allocBytes(n)
				copy(msg, buf[:n])
				fD := from.(types.Addr)
				fromDomain := types.Domain{
					Key:  make([]byte, ed25519.PublicKeySize),
					Name: make([]byte, ed25519.PublicKeySize),
				}
				copy(fromDomain.Name[:], fD.Name)
				copy(fromDomain.Key[:], fD.Key)
				m.pc.sessions.handleData(m, fromDomain, msg)
				m.Act(nil, rl) // continue to loop
			}
		}
		m.Act(nil, rl) // start the loop
	})
}
