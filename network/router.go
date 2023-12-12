package network

import (
	crand "crypto/rand"
	"encoding/binary"
	"time"

	//"fmt"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/types"
)

/***********
 * router *
 ***********/

/*

Potential showstopping issue (long term):
  Greedy routing using coords is fundamentally insecure.
    Nothing prevents a node from advertising the same port number to two different children.
    Everything downstream of the attacker is at risk of random blackholes etc.
    This costs the attacker essentially nothing.
  Workaround: use full keys.
    That obviously won't work for normal traffic -- it's too much info.
    It *may* work for protocol traffic, so we can use it for pathfinding.
    We could then e.g. build a source route along the way, and use the source route... if we can do that securely...
    Added benefit, we do expect source routing to be more stable in the face of tree flapping...
  Obvious issues with ygg v0.4 style source routing... alternatives?
    Detect if we've visited the same node before so we can drop traffic? How?
      Bloom filter would work, except for the issue of false positives...
      If we store a reverse route, we could send back an error, so the sender can resize the bloom filter... Seems messy...
    Bloom filter to track visited nodes, and if in the filter then add to a list? If in the list already, drop traffic entirely?

*/

type router struct {
	phony.Inbox
	core       *core
	pathfinder pathfinder                  // see pathfinder.go
	blooms     blooms                      // see bloomfilter.go
	peers      map[name]map[*peer]struct{} // True if we're allowed to send a mirror to this peer (but have not done so already)
	sent       map[name]map[name]struct{}  // tracks which info we've sent to our peer
	ports      map[peerPort]name           // used in tree lookups
	infos      map[name]routerInfo
	timers     map[name]*time.Timer
	ancs       map[name][]name // Peer ancestry info
	ancSeqs    map[name]uint64
	ancSeqCtr  uint64
	cache      map[name][]peerPort // Cache path slice for each peer
	requests   map[name]routerSigReq
	responses  map[name]routerSigRes
	resSeqs    map[name]uint64
	resSeqCtr  uint64
	refresh    bool
	doRoot1    bool
	doRoot2    bool
	mainTimer  *time.Timer
}

func (r *router) init(c *core) {
	r.core = c
	r.pathfinder.init(r)
	r.blooms.init(r)
	r.peers = make(map[name]map[*peer]struct{})
	r.sent = make(map[name]map[name]struct{})
	r.ports = make(map[peerPort]name)
	r.infos = make(map[name]routerInfo)
	r.timers = make(map[name]*time.Timer)
	r.ancs = make(map[name][]name)
	r.ancSeqs = make(map[name]uint64)
	r.cache = make(map[name][]peerPort)
	r.requests = make(map[name]routerSigReq)
	r.responses = make(map[name]routerSigRes)
	r.resSeqs = make(map[name]uint64)
	// Kick off actor to do initial work / become root
	r.mainTimer = time.AfterFunc(time.Second, func() {
		r.Act(nil, r._doMaintenance)
	})
	r.doRoot2 = true
	r.Act(nil, r._doMaintenance)
}

func (r *router) _doMaintenance() {
	if r.mainTimer == nil {
		return
	}
	r.doRoot2 = r.doRoot2 || r.doRoot1
	r._resetCache() // Resets path caches, since that info may no longer be good, TODO? don't wait for maintenance to do this
	r._updateAncestries()
	r._fix()           // Selects new parent, if needed
	r._sendAnnounces() // Sends announcements to peers, if needed
	r.blooms._doMaintenance()
	r.mainTimer.Reset(time.Second)
}

func (r *router) _shutdown() {
	if r.mainTimer != nil {
		r.mainTimer.Stop()
		r.mainTimer = nil
	}
	// TODO clean up pathfinder etc...
	//  There's a lot more to do here
}

func (r *router) _resetCache() {
	for k := range r.cache {
		delete(r.cache, k)
	}
}

func (r *router) addPeer(from phony.Actor, p *peer) {
	r.Act(from, func() {
		//r._resetCache()
		if _, isIn := r.peers[p.domain.name()]; !isIn {
			r.peers[p.domain.name()] = make(map[*peer]struct{})
			r.sent[p.domain.name()] = make(map[name]struct{})
			r.ports[p.port] = p.domain.name()
			r.ancSeqs[p.domain.name()] = r.ancSeqCtr
			r.blooms._addInfo(p.domain.name())
		} else {
			// Send anything we've already sent over previous peer connections to this node
			for k := range r.sent[p.domain.name()] {
				if info, isIn := r.infos[k]; isIn {
					p.sendAnnounce(r, info.getAnnounce(k))
				} else {
					panic("this should never happen")
				}
			}
		}
		r.peers[p.domain.name()][p] = struct{}{}
		if _, isIn := r.responses[p.domain.name()]; !isIn {
			if _, isIn := r.requests[p.domain.name()]; !isIn {
				r.requests[p.domain.name()] = *r._newReq()
			}
			req := r.requests[p.domain.name()]
			p.sendSigReq(r, &req)
		}
		r.blooms._sendBloom(p)
	})
}

func (r *router) removePeer(from phony.Actor, p *peer) {
	r.Act(from, func() {
		//r._resetCache()
		ps := r.peers[p.domain.name()]
		delete(ps, p)
		if len(ps) == 0 {
			delete(r.peers, p.domain.name())
			delete(r.sent, p.domain.name())
			delete(r.ports, p.port)
			delete(r.requests, p.domain.name())
			delete(r.responses, p.domain.name())
			delete(r.resSeqs, p.domain.name())
			delete(r.ancs, p.domain.name())
			delete(r.ancSeqs, p.domain.name())
			delete(r.cache, p.domain.name())
			r.blooms._removeInfo(p.domain.name())
			//r._fix()
		} else {
			// The bloom the remote node is tracking could be wrong due to a race
			// TODO? don't send it immediately, reset the "sent" state to blank so we'll resend next maintenance period
			for p := range ps {
				r.blooms._sendBloom(p)
			}
		}
	})
}

func (r *router) _clearReqs() {
	for k := range r.requests {
		delete(r.requests, k)
	}
	for k := range r.responses {
		delete(r.responses, k)
	}
	for k := range r.resSeqs {
		delete(r.resSeqs, k)
	}
	r.resSeqCtr = 0
}

func (r *router) _sendReqs() {
	r._clearReqs()
	for pk, ps := range r.peers {
		req := r._newReq()
		r.requests[pk] = *req
		for p := range ps {
			p.sendSigReq(r, req)
		}
	}
}

func (r *router) _updateAncestries() {
	r.ancSeqCtr++
	for pkey := range r.peers {
		anc := r._getAncestry(pkey)
		old := r.ancs[pkey]
		var diff bool
		if len(anc) != len(old) {
			diff = true
		} else {
			for idx := range anc {
				if anc[idx] != old[idx] {
					diff = true
					break
				}
			}
		}
		if diff {
			r.ancs[pkey] = anc
			r.ancSeqs[pkey] = r.ancSeqCtr
		}
	}
}

func (r *router) _fix() {
	bestRoot := r.core.crypto.domain.name()
	bestParent := r.core.crypto.domain.name()
	self := r.infos[r.core.crypto.domain.name()]
	// Check if our current parent leads to a better root than ourself
	if _, isIn := r.peers[self.parent]; isIn {
		root, _ := r._getRootAndDists(r.core.crypto.domain.name())
		if root.less(bestRoot) {
			bestRoot, bestParent = root, self.parent
		}
	}
	// Check if we know a better root/parent
	for pk := range r.responses {
		if _, isIn := r.infos[pk]; !isIn {
			// We don't know where this peer is
			continue
		}
		pRoot, pDists := r._getRootAndDists(pk)
		if _, isIn := pDists[r.core.crypto.domain.name()]; isIn {
			// This would loop through us already
			continue
		}
		if pRoot.less(bestRoot) {
			bestRoot, bestParent = pRoot, pk
		} else if pRoot != bestRoot {
			continue // wrong root
		}
		if r.ancSeqs[pk] < r.ancSeqs[bestParent] {
			// This node is advertising a more stable path, so we should probably switch to it...
			bestRoot, bestParent = pRoot, pk
		} else if r.ancSeqs[pk] != r.ancSeqs[bestParent] {
			continue // less stable path
		} else if /* r.refresh  || */ !bestParent.equal(self.parent) {
			// Equally good path (same anc seqs)
			// TODO? Update parents even if the old one works, if the new one is "better"
			//  But it has to be by a lot, stability is high priority (affects all downstream nodes)
			//  For now, if we're forced to select a new parent, then choose the "best" one
			//  Otherwise, just always keep the current parent if possible
			if pRoot == bestRoot && r.resSeqs[pk] < r.resSeqs[bestParent] {
				bestRoot, bestParent = pRoot, pk
			}
		}
	}
	if r.refresh || r.doRoot1 || r.doRoot2 || !self.parent.equal(bestParent) {
		res, isIn := r.responses[bestParent]
		switch {
		case isIn && !bestRoot.equal(r.core.crypto.domain.name()) && r._useResponse(bestParent, &res):
			// Somebody else should be root
			// Note that it's possible our current parent hasn't sent a res for our current req
			// (Link failure in progress, or from bad luck with timing)
			r.refresh = false
			r.doRoot1 = false
			r.doRoot2 = false
			r._sendReqs()
		case r.doRoot2:
			// Become root
			if !r._becomeRoot() {
				panic("this should never happen")
			}
			/*
				self = r.infos[r.core.crypto.publicKey]
				ann := self.getAnnounce(r.core.crypto.publicKey)
				for _, ps := range r.peers {
					for p := range ps {
						p.sendAnnounce(r, ann)
					}
				}
			*/
			r.refresh = false
			r.doRoot1 = false
			r.doRoot2 = false
			r._sendReqs()
		case !r.doRoot1:
			r.doRoot1 = true
			// No need to sendReqs in this case
			//  either we already have a req, or we've already requested one
			//  so resetting and re-requesting is just a waste of bandwidth
		default:
			// We need to self-root, but we already started a timer to do that later
			// So this is a no-op
		}
	}
}

func (r *router) _sendAnnounces() {
	// This is insanely delicate, lots of correctness is implicit across how nodes behave
	// Change nothing here.
	selfAnc := r._getAncestry(r.core.crypto.domain.name())
	var toSend []name
	var anns []*routerAnnounce

	for peerKey, sent := range r.sent {
		// Initial setup stuff
		toSend = toSend[:0]
		anns = anns[:0]
		peerAnc := r._getAncestry(peerKey)

		// Get whatever we haven't sent from selfAnc
		for _, k := range selfAnc {
			if _, isIn := sent[k]; !isIn {
				toSend = append(toSend, k)
				sent[k] = struct{}{}
			}
		}

		// Get whatever we haven't sent from peerAnc
		for _, k := range peerAnc {
			if _, isIn := sent[k]; !isIn {
				toSend = append(toSend, k)
				sent[k] = struct{}{}
			}
		}

		/*
			// Reset sent so it only contains the ancestry info
			for k := range sent {
				delete(sent, k)
			}
			for _, k := range selfAnc {
				sent[k] = struct{}{}
			}
			for _, k := range peerAnc {
				sent[k] = struct{}{}
			}
		*/

		// Now prepare announcements
		for _, k := range toSend {
			if info, isIn := r.infos[k]; isIn {
				anns = append(anns, info.getAnnounce(k))
			} else {
				panic("this should never happen")
			}
		}

		// Send announcements
		for p := range r.peers[peerKey] {
			for _, ann := range anns {
				p.sendAnnounce(r, ann)
			}
		}
	}
}

func (r *router) _newReq() *routerSigReq {
	var req routerSigReq
	nonce := make([]byte, 8)
	crand.Read(nonce) // If there's an error, there's not much to do...
	req.nonce = binary.BigEndian.Uint64(nonce)
	req.seq = r.infos[r.core.crypto.domain.name()].seq + 1
	return &req
}

func (r *router) _becomeRoot() bool {
	req := r._newReq()
	res := routerSigRes{
		routerSigReq: *req,
		port:         0, // TODO? something else?
	}
	res.psig = r.core.crypto.privateKey.sign(res.bytesForSig(r.core.crypto.domain.name(), r.core.crypto.domain.name()))
	ann := routerAnnounce{
		key:          r.core.crypto.domain,
		parent:       r.core.crypto.domain,
		routerSigRes: res,
		sig:          res.psig,
	}
	if !ann.check() {
		panic("this should never happen")
	}
	return r._update(&ann)
}

func (r *router) _handleRequest(p *peer, req *routerSigReq) {
	res := routerSigRes{
		routerSigReq: *req,
		port:         p.port,
	}
	res.psig = r.core.crypto.privateKey.sign(res.bytesForSig(p.domain.name(), r.core.crypto.domain.name()))
	p.sendSigRes(r, &res)
}

func (r *router) handleRequest(from phony.Actor, p *peer, req *routerSigReq) {
	r.Act(from, func() {
		r._handleRequest(p, req)
	})
}

func (r *router) _handleResponse(p *peer, res *routerSigRes) {
	if _, isIn := r.responses[p.domain.name()]; !isIn && r.requests[p.domain.name()] == res.routerSigReq {
		r.resSeqCtr++
		r.resSeqs[p.domain.name()] = r.resSeqCtr
		r.responses[p.domain.name()] = *res
		//r._fix() // This could become our new parent
	}
}

func (r *router) _useResponse(peerKey name, res *routerSigRes) bool {
	bs := res.bytesForSig(r.core.crypto.domain.name(), peerKey)
	info := routerInfo{
		parent:       peerKey,
		routerSigRes: *res,
		sig:          r.core.crypto.privateKey.sign(bs),
	}
	ann := info.getAnnounce(r.core.crypto.domain.name())
	if r._update(ann) {
		/*
			for _, ps := range r.peers {
				for p := range ps {
					p.sendAnnounce(r, ann)
				}
			}
		*/
		return true
	}
	return false
}

func (r *router) handleResponse(from phony.Actor, p *peer, res *routerSigRes) {
	r.Act(from, func() {
		r._handleResponse(p, res)
	})
}

func (r *router) _update(ann *routerAnnounce) bool {
	if info, isIn := r.infos[ann.key.name()]; isIn {
		switch {
		// Note: This logic *must* be the same on every node
		// If that's not true, then peers can infinitely spam announcements at each other for expired infos
		/*********************************
		 * XXX *** DO NOT CHANGE *** XXX *
		 *********************************/
		case info.seq > ann.seq:
			// This is an old seq, so exit
			return false
		case info.seq < ann.seq:
			// This is a newer seq, so don't exit
		case info.parent.less(ann.parent.name()):
			// same seq, worse (higher) parent
			return false
		case ann.parent.name().less(info.parent):
			// same seq, better (lower) parent, so don't exit
		case ann.nonce < info.nonce:
			// same seq and parent, lower nonce, so don't exit
		default:
			// same seq and parent, same or worse nonce, so exit
			return false
		}
	}
	// Clean up sent info and cache
	for _, sent := range r.sent {
		delete(sent, ann.key.name())
	}
	r._resetCache()
	// Save info
	info := routerInfo{
		parent:       ann.parent.name(),
		routerSigRes: ann.routerSigRes,
		sig:          ann.sig,
	}
	key := ann.key
	var timer *time.Timer
	if key.equal(r.core.crypto.domain) {
		delay := r.core.config.routerRefresh // TODO? slightly randomize
		timer = time.AfterFunc(delay, func() {
			r.Act(nil, func() {
				if r.timers[key.name()] == timer {
					r.refresh = true
					//r._fix()
				}
			})
		})
	} else {
		timer = time.AfterFunc(r.core.config.routerTimeout, func() {
			r.Act(nil, func() {
				if r.timers[key.name()] == timer {
					timer.Stop() // Shouldn't matter, but just to be safe...
					delete(r.infos, key.name())
					delete(r.timers, key.name())
					for _, sent := range r.sent {
						delete(sent, key.name())
					}
					r._resetCache()
					//r._fix()
				}
			})
		})
	}
	if oldTimer, isIn := r.timers[key.name()]; isIn {
		oldTimer.Stop()
	}
	r.timers[ann.key.name()] = timer
	r.infos[ann.key.name()] = info
	return true
}

func (r *router) _handleAnnounce(p *peer, ann *routerAnnounce) {
	if r._update(ann) {
		if ann.key.equal(r.core.crypto.domain) {
			// We just updated our own info from a message we received by a peer
			// That suggests we went offline, so our seq reset when we came back
			// The info they sent us could have been expired (see below in this function)
			// So we need to set that an update is required, as if our refresh timer has passed
			r.refresh = true
		}
		// No point in sending this back to the original sender
		r.sent[p.domain.name()][ann.key.name()] = struct{}{}
		//r._fix() // This could require us to change parents
	} else {
		// We didn't accept the info, because we alerady know it or something better
		info := routerInfo{
			parent:       ann.parent.name(),
			routerSigRes: ann.routerSigRes,
			sig:          ann.sig,
		}
		if oldInfo := r.infos[ann.key.name()]; info != oldInfo {
			// They sent something, but it was worse
			// Should we tell them what we know
			// Only to the p that sent it, since we'll spam the rest as messages arrive...
			r.sent[p.domain.name()][ann.key.name()] = struct{}{}
			p.sendAnnounce(r, oldInfo.getAnnounce(ann.key.name()))
		} else {
			// They sent us exactly the same info we already have
			// No point in sending it back when we do maintenance
			r.sent[p.domain.name()][ann.key.name()] = struct{}{}
		}
	}
}

func (r *router) handleAnnounce(from phony.Actor, p *peer, ann *routerAnnounce) {
	r.Act(from, func() {
		r._handleAnnounce(p, ann)
	})
}

func (r *router) sendTraffic(tr *traffic) {
	// This must be non-blocking, to prevent deadlocks between read/write paths in the encrypted package
	// Basically, WriteTo and ReadFrom can't be allowed to block each other, but they could if we allowed backpressure here
	// There may be a better way to handle this, but it practice it probably won't be an issue (we'll throw the packet in a queue somewhere, or drop it)
	r.Act(nil, func() {
		r.pathfinder._handleTraffic(tr)
	})
}

func (r *router) handleTraffic(from phony.Actor, tr *traffic) {
	r.Act(from, func() {
		if p := r._lookup(tr.path, &tr.watermark); p != nil {
			p.sendTraffic(r, tr)
		} else if tr.dest.publicKey() == r.core.crypto.publicKey {
			r.pathfinder._resetTimeout(tr.source.name())
			r.core.pconn.handleTraffic(r, tr)
		} else {
			// Not addressed to us, and we don't know a next hop.
			// The path is broken, so do something about that.
			r.pathfinder._doBroken(tr)
		}
	})
}

func (r *router) _getRootAndDists(dest name) (name, map[name]uint64) {
	// This returns the distances from the destination's root for the destination and each of its ancestors
	// Note that we skip any expired infos
	dists := make(map[name]uint64)
	next := dest
	var root name
	var dist uint64
	for {
		if _, isIn := dists[next]; isIn {
			break
		}
		if info, isIn := r.infos[next]; isIn {
			root = next
			dists[next] = dist
			dist++
			next = info.parent
		} else {
			break
		}
	}
	return root, dists
}

func (r *router) _getRootAndPath(dest name) (name, []peerPort) {
	var ports []peerPort
	visited := make(map[name]struct{})
	var root name
	next := dest
	for {
		if _, isIn := visited[next]; isIn {
			// We hit a loop
			return dest, nil
		}
		if info, isIn := r.infos[next]; isIn {
			root = next
			visited[next] = struct{}{}
			if next.equal(info.parent) {
				// We reached a root, don't append the self port (it should be zero anyway)
				break
			}
			ports = append(ports, info.port)
			next = info.parent
		} else {
			// We hit a dead end
			return dest, nil
		}
	}
	// Reverse order, since we built this from the node to the root
	for left, right := 0, len(ports)-1; left < right; left, right = left+1, right-1 {
		ports[left], ports[right] = ports[right], ports[left]
	}
	return root, ports
}

func (r *router) _getDist(destPath []peerPort, key name) uint64 {
	// We cache the keyPath to avoid allocating slices for every lookup
	var keyPath []peerPort
	if cached, isIn := r.cache[key]; isIn {
		keyPath = cached
	} else {
		_, keyPath = r._getRootAndPath(key)
		r.cache[key] = keyPath
	}
	end := len(destPath)
	if len(keyPath) < end {
		end = len(keyPath)
	}
	dist := uint64(len(keyPath) + len(destPath))
	for idx := 0; idx < end; idx++ {
		if keyPath[idx] == destPath[idx] {
			dist -= 2
		} else {
			break
		}
	}
	return dist
}

func (r *router) _lookup(path []peerPort, watermark *uint64) *peer {
	// Look up the next hop (in treespace) towards the destination
	var bestPeer *peer
	bestDist := ^uint64(0)
	if watermark != nil {
		if dist := r._getDist(path, r.core.crypto.domain.name()); dist < *watermark {
			bestDist = dist // Self dist, so other nodes must be strictly better by distance
			*watermark = dist
		} else {
			return nil
		}
	}
	tiebreak := func(key name) bool {
		// If distances match, keep the peer with the lowest key, just so there's some kind of consistency
		return bestPeer != nil && key.less(bestPeer.domain.name())
	}
	for k, ps := range r.peers {
		if dist := r._getDist(path, k); dist < bestDist || (dist == bestDist && tiebreak(k)) {
			for p := range ps {
				// Set the next hop to any peer object for this peer
				bestPeer = p
				bestDist = dist
				break
			}
			for p := range ps {
				// Find the best peer object for this peer
				switch {
				case bestPeer != nil && p.prio > bestPeer.prio:
					// Skip worse priority links
					continue
				case bestPeer != nil && p.time.After(bestPeer.time):
					// Skip links that have been up for less time
					continue
				default:
					bestPeer = p
				}
			}
		}
	}
	return bestPeer
}

func (r *router) _getAncestry(key name) []name {
	// Returns the ancestry starting with the root side, ordering is important for how we send over the network / GC info...
	anc := r._backwardsAncestry(key)
	for left, right := 0, len(anc)-1; left < right; left, right = left+1, right-1 {
		anc[left], anc[right] = anc[right], anc[left]
	}
	return anc
}

func (r *router) _backwardsAncestry(key name) []name {
	// Return an ordered list of node ancestry, starting with the given key and ending at the root (or the end of the line)
	var anc []name
	here := key
	for {
		// TODO? use a map or something to check visited nodes faster?
		for _, k := range anc {
			if k == here {
				return anc
			}
		}
		if info, isIn := r.infos[here]; isIn {
			anc = append(anc, here)
			here = info.parent
			continue
		}
		// Dead end
		return anc
	}
}

/*****************
 * routerSigReq *
 *****************/

type routerSigReq struct {
	seq   uint64
	nonce uint64
}

func (req *routerSigReq) bytesForSig(node, parent name) []byte {
	out := make([]byte, 0, publicKeySize*2+8+8)
	out = append(out, node[:]...)
	out = append(out, parent[:]...)
	out, _ = req.encode(out)
	return out
}

func (req *routerSigReq) size() int {
	size := wireSizeUint(req.seq)
	size += wireSizeUint(req.nonce)
	return size
}

func (req *routerSigReq) encode(out []byte) ([]byte, error) {
	start := len(out)
	out = wireAppendUint(out, req.seq)
	out = wireAppendUint(out, req.nonce)
	end := len(out)
	if end-start != req.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (req *routerSigReq) chop(data *[]byte) error {
	var tmp routerSigReq
	orig := *data
	if !wireChopUint(&tmp.seq, &orig) {
		return types.ErrDecode
	} else if !wireChopUint(&tmp.nonce, &orig) {
		return types.ErrDecode
	}
	*req = tmp
	*data = orig
	return nil
}

func (req *routerSigReq) decode(data []byte) error {
	var tmp routerSigReq
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*req = tmp
	return nil
}

/*****************
 * routerSigRes *
 *****************/

type routerSigRes struct {
	routerSigReq
	port peerPort
	psig signature
}

func (res *routerSigRes) check(node, parent domain) bool {
	bs := res.bytesForSig(node.name(), parent.name())
	return parent.verify(bs, &res.psig)
}

func (res *routerSigRes) bytesForSig(node, parent name) []byte {
	bs := res.routerSigReq.bytesForSig(node, parent)
	bs = wireAppendUint(bs, uint64(res.port))
	return bs
}

func (res *routerSigRes) size() int {
	size := res.routerSigReq.size()
	size += wireSizeUint(uint64(res.port))
	size += len(res.psig)
	return size
}

func (res *routerSigRes) encode(out []byte) ([]byte, error) {
	start := len(out)
	var err error
	out, err = res.routerSigReq.encode(out)
	if err != nil {
		return nil, err
	}
	out = wireAppendUint(out, uint64(res.port))
	out = append(out, res.psig[:]...)
	end := len(out)
	if end-start != res.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (res *routerSigRes) chop(data *[]byte) error {
	orig := *data
	var tmp routerSigRes
	if err := tmp.routerSigReq.chop(&orig); err != nil {
		return err
	} else if !wireChopUint((*uint64)(&tmp.port), &orig) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.psig[:], &orig) {
		return types.ErrDecode
	}
	*res = tmp
	*data = orig
	return nil
}

func (res *routerSigRes) decode(data []byte) error {
	var tmp routerSigRes
	if err := tmp.chop(&data); err != nil {
		return err
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*res = tmp
	return nil
}

/*******************
 * routerAnnounce *
 *******************/

type routerAnnounce struct {
	key    domain
	parent domain
	routerSigRes
	sig signature
}

func (ann *routerAnnounce) check() bool {
	if ann.port == 0 && !ann.key.equal(ann.parent) {
		return false
	}
	bs := ann.bytesForSig(ann.key.name(), ann.parent.name())
	return ann.key.verify(bs, &ann.sig) && ann.parent.verify(bs, &ann.psig)
}

func (ann *routerAnnounce) size() int {
	size := len(ann.key.Key)
	size += len(ann.parent.Key)
	size += len(ann.key.Name)
	size += len(ann.parent.Name)
	size += ann.routerSigRes.size()
	size += len(ann.sig)
	return size
}

func (ann *routerAnnounce) encode(out []byte) ([]byte, error) {
	start := len(out)
	var err error
	out = append(out, ann.key.Key[:]...)
	out = append(out, ann.parent.Key[:]...)
	out = append(out, ann.key.Name[:]...)
	out = append(out, ann.parent.Name[:]...)
	out, err = ann.routerSigRes.encode(out)
	if err != nil {
		return nil, err
	}
	out = append(out, ann.sig[:]...)
	end := len(out)
	if end-start != ann.size() {
		panic("this should never happen")
	}
	return out, nil
}

func (ann *routerAnnounce) decode(data []byte) error {
	var tmp routerAnnounce
	if !wireChopSlice(tmp.key.Key[:], &data) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.parent.Key[:], &data) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.key.Name[:], &data) {
		return types.ErrDecode
	} else if !wireChopSlice(tmp.parent.Name[:], &data) {
		return types.ErrDecode
	} else if err := tmp.routerSigRes.chop(&data); err != nil {
		return err
	} else if !wireChopSlice(tmp.sig[:], &data) {
		return types.ErrDecode
	} else if len(data) != 0 {
		return types.ErrDecode
	}
	*ann = tmp
	return nil
}

/***************
 * routerInfo *
 ***************/

// This is the value stored in a key,value map

type routerInfo struct {
	parent name
	routerSigRes
	sig signature
}

func (info *routerInfo) getAnnounce(key name) *routerAnnounce {
	return &routerAnnounce{
		key:          key,
		parent:       info.parent,
		routerSigRes: info.routerSigRes,
		sig:          info.sig,
	}
}

/****************
 * routerForget *
 ****************/

type routerForget struct {
	routerAnnounce
}
