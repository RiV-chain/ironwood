package network

import (
	"time"

	"github.com/Arceliar/ironwood/types"
)

const pathfinderTrafficCache = true

// WARNING The pathfinder should only be used from within the router's actor, it's not threadsafe
type pathfinder struct {
	router *router
	info   pathNotifyInfo
	paths  map[name]pathInfo
	rumors map[name]pathRumor
	logger func(*pathLookup)
}

func (pf *pathfinder) init(r *router) {
	pf.router = r
	pf.info.sign(pf.router.core.crypto.privateKey)
	pf.paths = make(map[name]pathInfo)
	pf.rumors = make(map[name]pathRumor)
}

func (pf *pathfinder) _sendLookup(dest domain) {
	if info, isIn := pf.paths[dest.name()]; isIn {
		if time.Since(info.reqTime) < pf.router.core.config.pathThrottle {
			// Don't flood with request, wait a bit
			return
		}
	}
	selfKey := pf.router.core.crypto.domain
	_, from := pf.router._getRootAndPath(selfKey.name())
	lookup := pathLookup{
		source: selfKey,
		dest:   dest,
		from:   from,
	}
	pf._handleLookup(lookup.source.name(), &lookup)
}

func (pf *pathfinder) handleLookup(p *peer, lookup *pathLookup) {
	pf.router.Act(p, func() {
		if !pf.router.blooms._isOnTree(p.domain.name()) {
			return
		}
		pf._handleLookup(p.domain.name(), lookup)
	})
}

func (pf *pathfinder) _handleLookup(fromKey name, lookup *pathLookup) {
	if pf.logger != nil {
		pf.logger(lookup)
	}
	// Continue the multicast
	pf.router.blooms._sendMulticast(lookup, fromKey, lookup.dest.name())
	// Check if we should send a response too
	dx := pf.router.blooms.xKey(lookup.dest.name())
	sx := pf.router.blooms.xKey(pf.router.core.crypto.domain.name())
	if dx == sx {
		// We match, send a response
		// TODO? throttle this per dest that we're sending a response to?
		_, path := pf.router._getRootAndPath(pf.router.core.crypto.domain.name())
		notify := pathNotify{
			path:      lookup.from,
			watermark: ^uint64(0),
			source:    pf.router.core.crypto.domain,
			dest:      lookup.source,
			info: pathNotifyInfo{
				seq:  uint64(time.Now().Unix()), //pf.info.seq,
				path: path,
			},
		}
		if !pf.info.equal(notify.info) {
			//notify.info.seq++
			notify.info.sign(pf.router.core.crypto.privateKey)
			pf.info = notify.info
		} else {
			notify.info = pf.info
		}
		pf._handleNotify(notify.source.name(), &notify)
	}
}

func (pf *pathfinder) handleNotify(p *peer, notify *pathNotify) {
	pf.router.Act(p, func() {
		pf._handleNotify(p.domain.name(), notify)
	})
}

func (pf *pathfinder) _handleNotify(fromKey name, notify *pathNotify) {
	if p := pf.router._lookup(notify.path, &notify.watermark); p != nil {
		p.sendPathNotify(pf.router, notify)
		return
	}
	// Check if we should accept this response
	if !notify.dest.equal(pf.router.core.crypto.domain) {
		return
	}
	var info pathInfo
	var isIn bool
	// Note that we need to res.check() in every case (as soon as success is otherwise inevitable)
	if info, isIn = pf.paths[notify.source.name()]; isIn {
		if notify.info.seq <= info.seq {
			// This isn't newer than the last seq we received, so drop it
			return
		}
		nfo := notify.info
		nfo.path = info.path
		if nfo.equal(notify.info) {
			// This doesn't actually add anything new, so skip it
			return
		}
		if !notify.check() {
			return
		}
		info.timer.Reset(pf.router.core.config.pathTimeout)
	} else {
		xform := pf.router.blooms.xKey(notify.source.name())
		if _, isIn := pf.rumors[xform]; !isIn {
			return
		}
		if !notify.check() {
			return
		}
		key := notify.source
		var timer *time.Timer
		timer = time.AfterFunc(pf.router.core.config.pathTimeout, func() {
			pf.router.Act(nil, func() {
				if info := pf.paths[key.name()]; info.timer == timer {
					timer.Stop()
					delete(pf.paths, key.name())
					if info.traffic != nil {
						freeTraffic(info.traffic)
					}
				}
			})
		})
		info = pathInfo{
			reqTime: time.Now(),
			timer:   timer,
		}
		if rumor := pf.rumors[xform]; rumor.traffic != nil && rumor.traffic.dest.name() == notify.source.name() {
			info.traffic = rumor.traffic
			rumor.traffic = nil
			pf.rumors[xform] = rumor
		}
	}
	info.path = notify.info.path
	info.seq = notify.info.seq
	info.broken = false
	if info.traffic != nil {
		tr := info.traffic
		info.traffic = nil
		// We defer so it happens after we've store the updated info in the map
		defer pf._handleTraffic(tr)
	}
	pf.paths[notify.source.name()] = info
	pf.router.core.config.pathNotify(notify.source.name())
}

func (pf *pathfinder) _rumorSendLookup(dest domain) {
	xform := pf.router.blooms.xKey(dest.name())
	if rumor, isIn := pf.rumors[xform]; isIn {
		if time.Since(rumor.sendTime) < pf.router.core.config.pathThrottle {
			return
		}
		rumor.sendTime = time.Now()
		rumor.timer.Reset(pf.router.core.config.pathTimeout)
		pf.rumors[xform] = rumor
	} else {
		var timer *time.Timer
		timer = time.AfterFunc(pf.router.core.config.pathTimeout, func() {
			pf.router.Act(nil, func() {
				if rumor := pf.rumors[xform]; rumor.timer == timer {
					delete(pf.rumors, xform)
					timer.Stop()
					if rumor.traffic != nil {
						freeTraffic(rumor.traffic)
					}
				}
			})
		})
		pf.rumors[xform] = pathRumor{
			sendTime: time.Now(),
			timer:    timer,
		}
	}
	pf._sendLookup(dest)
}

func (pf *pathfinder) _handleTraffic(tr *traffic) {
	const cache = pathfinderTrafficCache // TODO make this unconditional, this is just to easily toggle the cache on/off for now
	if info, isIn := pf.paths[tr.dest.name()]; isIn {
		tr.path = append(tr.path[:0], info.path...)
		_, from := pf.router._getRootAndPath(pf.router.core.crypto.domain.name())
		tr.from = append(tr.from[:0], from...)
		if cache {
			if info.traffic != nil {
				freeTraffic(info.traffic)
			}
			info.traffic = allocTraffic()
			info.traffic.copyFrom(tr)
			pf.paths[tr.dest.name()] = info
		}
		pf.router.handleTraffic(nil, tr)
	} else {
		pf._rumorSendLookup(tr.dest)
		if cache {
			xform := pf.router.blooms.xKey(tr.dest.name())
			if rumor, isIn := pf.rumors[xform]; isIn {
				if rumor.traffic != nil {
					freeTraffic(rumor.traffic)
				}
				rumor.traffic = tr
				pf.rumors[xform] = rumor
			} else {
				panic("this should never happen")
			}
		}
	}
}

func (pf *pathfinder) _doBroken(tr *traffic) {
	broken := pathBroken{
		path:      append([]peerPort(nil), tr.from...),
		watermark: ^uint64(0),
		source:    tr.source,
		dest:      tr.dest,
	}
	pf._handleBroken(&broken)
}

func (pf *pathfinder) _handleBroken(broken *pathBroken) {
	// Hack using traffic to do routing
	if p := pf.router._lookup(broken.path, &broken.watermark); p != nil {
		p.sendPathBroken(pf.router, broken)
		return
	}
	// Check if we should accept this pathBroken
	if !broken.source.equal(pf.router.core.crypto.domain) {
		return
	}
	if info, isIn := pf.paths[broken.dest.name()]; isIn {
		info.broken = true
		pf.paths[broken.dest.name()] = info
		pf._sendLookup(broken.dest) // Throttled inside this function
	}
}

func (pf *pathfinder) handleBroken(p *peer, broken *pathBroken) {
	pf.router.Act(p, func() {
		pf._handleBroken(broken)
	})
}

func (pf *pathfinder) _resetTimeout(key name) {
	// Note: We should call this when we receive a packet from this destination
	// We should *not* reset just because we tried to send a packet
	// We need things to time out eventually if e.g. a node restarts and resets its seqs
	if info, isIn := pf.paths[key]; isIn && !info.broken {
		info.timer.Reset(pf.router.core.config.pathTimeout)
	}
}

/************
 * pathInfo *
 ************/

type pathInfo struct {
	path    []peerPort // *not* zero terminated (and must be free of zeros)
	seq     uint64
	reqTime time.Time   // Time a request was last sent (to prevent spamming)
	timer   *time.Timer // time.AfterFunc(cleanup...), reset whenever we receive traffic from this node
	traffic *traffic
	broken  bool // Set to true if we receive a pathBroken, which prevents the timer from being reset (we must get a new notify to clear)
}

/*************
 * pathRumor *
 *************/
type pathRumor struct {
	traffic  *traffic
	sendTime time.Time   // Time we last sent a rumor (to prevnt spamming)
	timer    *time.Timer // time.AfterFunc(cleanup...)
}

/**************
 * pathLookup *
 **************/

type pathLookup struct {
	source domain
	dest   domain
	from   []peerPort
}

func (lookup *pathLookup) size() int {
	size := len(lookup.source.Key)
	size += len(lookup.dest.Key)
	size += len(lookup.source.Name)
	size += len(lookup.dest.Name)
	size += wireSizePath(lookup.from)
	return size
}

func (lookup *pathLookup) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = append(out, lookup.source.Key[:]...)
	out = append(out, lookup.dest.Key[:]...)
	out = append(out, lookup.source.Name[:]...)
	out = append(out, lookup.dest.Name[:]...)
	out = wireAppendPath(out, lookup.from)
	end := len(out)
	if end-start != lookup.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (lookup *pathLookup) decode(data []byte) error {
	var tmp pathLookup
	orig := data
	if !wireChopSlice(tmp.source.Key[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest.Key[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.source.Name[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest.Name[:], &orig) {
		return types.ErrDecode
	} else if !wireChopPath(&tmp.from, &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*lookup = tmp
	return nil
}

// Needed for pqPacket interface

func (lookup *pathLookup) wireType() wirePacketType {
	return wireProtoPathLookup
}

func (lookup *pathLookup) sourceKey() domain {
	return lookup.source
}

func (lookup *pathLookup) destKey() domain {
	return lookup.dest
}

/******************
 * pathNotifyInfo *
 ******************/

type pathNotifyInfo struct {
	seq  uint64
	path []peerPort // Path from root to source, aka coords, zero-terminated
	sig  signature  // signature from the source key
}

// equal returns true if the pathResponseInfos are equal, inspecting the contents of the path and ignoring the sig
func (info *pathNotifyInfo) equal(cmp pathNotifyInfo) bool {
	if info.seq != cmp.seq {
		return false
	} else if len(info.path) != len(cmp.path) {
		return false
	}
	for idx := range info.path {
		if info.path[idx] != cmp.path[idx] {
			return false
		}
	}
	return true
}

func (info *pathNotifyInfo) bytesForSig() []byte {
	var out []byte
	out = wireAppendUint(out, info.seq)
	out = wireAppendPath(out, info.path)
	return out
}

func (info *pathNotifyInfo) sign(key privateKey) {
	info.sig = key.sign(info.bytesForSig())
}

func (info *pathNotifyInfo) size() int {
	size := wireSizeUint(info.seq)
	size += wireSizePath(info.path)
	size += len(info.sig)
	return size
}

func (info *pathNotifyInfo) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, info.seq)
	out = wireAppendPath(out, info.path)
	out = append(out, info.sig[:]...)
	end := len(out)
	if end-start != info.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (info *pathNotifyInfo) decode(data []byte) error {
	var tmp pathNotifyInfo
	orig := data
	if !wireChopUint(&tmp.seq, &orig) {
		return types.ErrDecode
	} else if !wireChopPath(&tmp.path, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.sig[:], &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*info = tmp
	return nil
}

/**************
 * pathNotify *
 **************/

type pathNotify struct {
	path      []peerPort
	watermark uint64
	source    domain // who sent the response, not who resquested it
	dest      domain // exact key we are sending response to
	info      pathNotifyInfo
}

func (notify *pathNotify) check() bool {
	return notify.source.verify(notify.info.bytesForSig(), &notify.info.sig)
}

func (notify *pathNotify) size() int {
	size := wireSizePath(notify.path)
	size += wireSizeUint(notify.watermark)
	size += len(notify.source.Key)
	size += len(notify.dest.Key)
	size += len(notify.source.Name)
	size += len(notify.dest.Name)
	size += notify.info.size()
	return size
}

func (notify *pathNotify) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendPath(out, notify.path)
	out = wireAppendUint(out, notify.watermark)
	out = append(out, notify.source.Key[:]...)
	out = append(out, notify.dest.Key[:]...)
	out = append(out, notify.source.Name[:]...)
	out = append(out, notify.dest.Name[:]...)
	var err error
	if out, err = notify.info.encode(out); err != nil {
		return nil, err
	}
	end := len(out)
	if end-start != notify.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (notify *pathNotify) decode(data []byte) error {
	var tmp pathNotify
	orig := data
	if !wireChopPath(&tmp.path, &orig) {
		return types.ErrDecode
	} else if !wireChopUint(&tmp.watermark, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.source.Key[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest.Key[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.source.Name[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest.Name[:], &orig) {
		return types.ErrDecode
	} else if err := tmp.info.decode(orig); err != nil {
		return err
	}
	*notify = tmp
	return nil
}

func (notify *pathNotify) wireType() wirePacketType {
	return wireProtoPathNotify
}

func (notify *pathNotify) sourceKey() domain {
	return notify.source
}

func (notify *pathNotify) destKey() domain {
	return notify.dest
}

/**************
 * pathBroken *
 **************/

type pathBroken struct {
	path      []peerPort
	watermark uint64
	source    domain
	dest      domain
}

func (broken *pathBroken) size() int {
	size := wireSizePath(broken.path)
	size += wireSizeUint(broken.watermark)
	size += len(broken.source.Key)
	size += len(broken.dest.Key)
	size += len(broken.source.Name)
	size += len(broken.dest.Name)
	return size
}

func (broken *pathBroken) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendPath(out, broken.path)
	out = wireAppendUint(out, broken.watermark)
	out = append(out, broken.source.Key[:]...)
	out = append(out, broken.dest.Key[:]...)
	out = append(out, broken.source.Name[:]...)
	out = append(out, broken.dest.Name[:]...)
	end := len(out)
	if end-start != broken.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (broken *pathBroken) decode(data []byte) error {
	var tmp pathBroken
	orig := data
	if !wireChopPath(&tmp.path, &orig) {
		return types.ErrDecode
	} else if !wireChopUint(&tmp.watermark, &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.source.Key[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest.Key[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.source.Name[:], &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.dest.Name[:], &orig) {
		return types.ErrDecode
	} else if len(orig) != 0 {
		return types.ErrDecode
	}
	*broken = tmp
	return nil
}

func (broken *pathBroken) wireType() wirePacketType {
	return wireProtoPathBroken
}

func (broken *pathBroken) sourceKey() domain {
	return broken.source
}

func (broken *pathBroken) destKey() domain {
	return broken.dest
}
