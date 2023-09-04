package network

import (
	"crypto/ed25519"
	"net"
	"time"

	"github.com/Arceliar/ironwood/types"
	"github.com/Arceliar/phony"
)

type Debug struct {
	c *core
}

func (d *Debug) init(c *core) {
	d.c = c
}

type DebugLabelInfo struct {
	Sig    []byte
	Domain types.Domain
	Root   types.Domain
	Seq    uint64
	Path   []uint64
}

type DebugSelfInfo struct {
	Domain  types.Domain
	Root    types.Domain
	Coords  []uint64
	Updated time.Time
}

type DebugPeerInfo struct {
	Domain   types.Domain
	Root     types.Domain
	Coords   []uint64
	Port     uint64
	Updated  time.Time
	Conn     net.Conn
	Priority uint8
}

type DebugDHTInfo struct {
	Domain types.Domain
	Port   uint64
	Rest   uint64
}

type DebugPathInfo struct {
	Key  ed25519.PublicKey
	Path []uint64
}

func (d *Debug) GetLabel() (info DebugLabelInfo) {
	phony.Block(&d.c.dhtree, func() {
		l := d.c.dhtree._getLabel()
		info = DebugLabelInfo{
			Domain: types.Domain(l.domain),
			Root:   types.Domain(l.root),
			Sig:    []byte(l.sig[:]),
			Seq:    l.seq,
		}
		info.Path = make([]uint64, 0)
		for _, port := range l.path {
			info.Path = append(info.Path, uint64(port))
		}
	})
	return
}

func (d *Debug) GetSelf() (info DebugSelfInfo) {
	phony.Block(&d.c.dhtree, func() {
		info.Domain = types.Domain(d.c.crypto.domain)
		info.Root = types.Domain(d.c.dhtree.self.root)
		info.Coords = make([]uint64, 0)
		for _, hop := range d.c.dhtree.self.hops {
			info.Coords = append(info.Coords, uint64(hop.port))
		}
		info.Updated = d.c.dhtree.self.time
	})
	return
}

func (d *Debug) GetPeers() (infos []DebugPeerInfo) {
	phony.Block(&d.c.dhtree, func() {
		for p, tinfo := range d.c.dhtree.tinfos {
			var info DebugPeerInfo
			info.Domain = types.Domain(p.domain)
			info.Root = types.Domain(tinfo.root)
			info.Coords = make([]uint64, 0)
			for _, hop := range tinfo.hops {
				info.Coords = append(info.Coords, uint64(hop.port))
			}
			info.Coords = info.Coords[:len(info.Coords)-1] // Last hop is the port back to self
			info.Port = uint64(p.port)
			info.Updated = tinfo.time
			info.Conn = p.conn
			info.Priority = p.prio
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetDHT() (infos []DebugDHTInfo) {
	phony.Block(&d.c.dhtree, func() {
		for _, dinfo := range d.c.dhtree.dinfos {
			var info DebugDHTInfo
			info.Domain = types.Domain(dinfo.key)
			if dinfo.peer != nil {
				info.Port = uint64(dinfo.peer.port)
			}
			if dinfo.rest != nil {
				info.Rest = uint64(dinfo.rest.port)
			}
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetPaths() (infos []DebugPathInfo) {
	phony.Block(&d.c.dhtree, func() {
		for key, pinfo := range d.c.dhtree.pathfinder.paths {
			var info DebugPathInfo
			info.Key = append(info.Key, key[:]...)
			info.Path = make([]uint64, 0)
			for _, port := range pinfo.path {
				info.Path = append(info.Path, uint64(port))
			}
			infos = append(infos, info)
		}
	})
	return
}
