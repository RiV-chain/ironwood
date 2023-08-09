package network

import (
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
	Domain types.Domain
	Path   []uint64
}

func (d *Debug) GetSelf() (info DebugSelfInfo) {
	phony.Block(&d.c.dhtree, func() {
		info.Domain = append(info.Domain, d.c.crypto.domain[:]...)
		info.Root = append(info.Root, d.c.dhtree.self.root[:]...)
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
			info.Domain = append(info.Domain, p.domain[:]...)
			info.Root = append(info.Root, tinfo.root[:]...)
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
			info.Domain = append(info.Domain, dinfo.domain[:]...)
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
		for domain, pinfo := range d.c.dhtree.pathfinder.paths {
			var info DebugPathInfo
			info.Domain = append(info.Domain, domain[:]...)
			info.Path = make([]uint64, 0)
			for _, port := range pinfo.path {
				info.Path = append(info.Path, uint64(port))
			}
			infos = append(infos, info)
		}
	})
	return
}
