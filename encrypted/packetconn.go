package encrypted

import (
	"crypto/ed25519"
	"errors"
	"net"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/types"
)

type PacketConn struct {
	actor phony.Inbox
	*network.PacketConn
	secretEd  edPriv
	secretBox boxPriv
	sessions  sessionManager
	network   netManager
	Debug     Debug
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey, domain types.Domain) (*PacketConn, error) {
	npc, err := network.NewPacketConn(secret, domain)
	if err != nil {
		return nil, err
	}
	pc := &PacketConn{PacketConn: npc}
	copy(pc.secretEd[:], secret[:])
	pc.secretBox = *pc.secretEd.toBox()
	pc.sessions.init(pc)
	pc.network.init(pc)
	pc.Debug.init(pc)
	return pc, nil
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	pc.network.read()
	info := <-pc.network.readCh
	if info.err != nil {
		err = info.err
		return
	}
	// info.from.asKey()
	n, from = len(info.data), types.Addr(info.from)
	if n > len(p) {
		n = len(p)
	}
	copy(p, info.data[:n])
	return
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-pc.network.closed:
		return 0, errors.New("closed")
	default:
	}
	dest, ok := addr.(types.Addr)
	destDomain := types.Domain(dest)
	if !ok || len(destDomain.Key) != edPubSize {
		return 0, errors.New("bad destination key length")
	}
	if uint64(len(p)) > pc.MTU() {
		return 0, errors.New("oversized message")
	}
	n = len(p)
	buf := pc.sessions.pool.Get().([]byte)[:0]
	buf = append(buf, p...)
	pc.sessions.writeTo(destDomain, buf)
	return
}

// MTU returns the maximum transmission unit of the PacketConn, i.e. maximum safe message size to send over the network.
func (pc *PacketConn) MTU() uint64 {
	return pc.PacketConn.MTU() - sessionTrafficOverhead
}
