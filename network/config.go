package network

import (
	"time"
)

type config struct {
	routerRefresh      time.Duration
	routerTimeout      time.Duration
	peerKeepAliveDelay time.Duration
	peerTimeout        time.Duration
	peerMaxMessageSize uint64
	bloomTransform     func([publicKeySize]byte) [publicKeySize]byte
	pathNotify         func([publicKeySize]byte)
	pathTimeout        time.Duration
	pathThrottle       time.Duration
}

type Option func(*config)

func configDefaults() Option {
	return func(c *config) {
		c.routerRefresh = 4 * time.Minute
		c.routerTimeout = 5 * time.Minute
		c.peerKeepAliveDelay = time.Second
		c.peerTimeout = 3 * time.Second
		c.peerMaxMessageSize = 1048576 // 1 megabyte
		c.bloomTransform = func(key [publicKeySize]byte) [publicKeySize]byte { return key }
		c.pathNotify = func(key [publicKeySize]byte) {}
		c.pathTimeout = time.Minute
		c.pathThrottle = time.Second
	}
}

func WithRouterRefresh(duration time.Duration) Option {
	return func(c *config) {
		c.routerRefresh = duration
	}
}

func WithRouterTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.routerTimeout = duration
	}
}

func WithPeerKeepAliveDelay(duration time.Duration) Option {
	return func(c *config) {
		c.peerKeepAliveDelay = duration
	}
}

func WithPeerTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.peerTimeout = duration
	}
}

func WithPeerMaxMessageSize(size uint64) Option {
	return func(c *config) {
		c.peerMaxMessageSize = size
	}
}

func WithBloomTransform(xform func(key [32]byte) [32]byte) Option {
	return func(c *config) {
		c.bloomTransform = xform
	}
}

func WithPathNotify(notify func(key [32]byte)) Option {
	return func(c *config) {
		c.pathNotify = notify
	}
}

func WithPathTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.pathTimeout = duration
	}
}

func WithPathThrottle(duration time.Duration) Option {
	return func(c *config) {
		c.pathThrottle = duration
	}
}
