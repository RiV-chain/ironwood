package encrypted

import (
	"time"

	"github.com/Arceliar/ironwood/types"
	"github.com/Arceliar/phony"
)

type Debug struct {
	pc *PacketConn
}

func (d *Debug) init(pc *PacketConn) {
	d.pc = pc
}

type DebugSessionInfo struct {
	Domain types.Domain
	Uptime time.Duration
	RX     uint64
	TX     uint64
}

func (d *Debug) GetSessions() (infos []DebugSessionInfo) {
	phony.Block(&d.pc.sessions, func() {
		for _, session := range d.pc.sessions.sessions {
			var info DebugSessionInfo
			info.Domain = session.domain
			info.Uptime = time.Since(session.since)
			info.RX, info.TX = session.rx, session.tx
			infos = append(infos, info)
		}
	})
	return
}
