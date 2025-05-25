package client

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/errors"

	"github.com/sagernet/quic-go"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

type Config struct {
	ConnFactory     ConnFactory
	ServerAddr      net.Addr
	Auth            string
	TLSConfig       *tls.Config
	QUICConfig      *quic.Config
	BandwidthConfig BandwidthConfig
	FastOpen        bool

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ConnFactory == nil {
		c.ConnFactory = &udpConnFactory{}
	}
	if c.ServerAddr == nil {
		return errors.ConfigError{Field: "ServerAddr", Reason: "must be set"}
	}
	c.filled = true
	return nil
}

type ConnFactory interface {
	New(net.Addr) (net.PacketConn, error)
}

type udpConnFactory struct{}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
