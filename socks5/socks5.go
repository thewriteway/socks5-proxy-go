// Package socks5 implements a lightweight SOCKS5 proxy server.
// Inspired by github.com/armon/go-socks5, simplified and Docker-ready.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// SOCKS5 protocol constants
const (
	socks5Version = uint8(5)

	// Auth methods
	authNone     = uint8(0)
	authPassword = uint8(2)
	authNoAccept = uint8(255)

	// Sub-negotiation version for user/pass auth
	authPasswordVersion = uint8(1)
	authSuccess         = uint8(0)
	authFailure         = uint8(1)

	// Commands
	cmdConnect = uint8(1)

	// Address types
	atypIPv4   = uint8(1)
	atypDomain = uint8(3)
	atypIPv6   = uint8(4)

	// Reply codes
	repSuccess         = uint8(0)
	repServerFailure   = uint8(1)
	repNotAllowed      = uint8(2)
	repNetUnreachable  = uint8(3)
	repHostUnreachable = uint8(4)
	repConnRefused     = uint8(5)
	repCmdNotSupported = uint8(7)
	repAddrNotSupported = uint8(8)
)

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------

// Credentials is a simple username → password map used for auth.
type Credentials map[string]string

// Config holds all tuneable options for the SOCKS5 server.
type Config struct {
	// Credentials enables username/password auth when non-nil.
	// If nil the server advertises "no auth required".
	Credentials Credentials

	// Resolver overrides DNS resolution. Defaults to net.DefaultResolver.
	Resolver *net.Resolver

	// DialTimeout is the timeout when connecting to the upstream target.
	// Defaults to 10 s.
	DialTimeout time.Duration

	// Logger is used for diagnostic output. Defaults to the standard logger.
	Logger *log.Logger

	// Rules optionally restricts which destinations are allowed.
	// Return false to deny. If nil all destinations are permitted.
	Rules func(ctx context.Context, addr AddrSpec) bool
}

func (c *Config) defaults() {
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	if c.Resolver == nil {
		c.Resolver = net.DefaultResolver
	}
}

// -----------------------------------------------------------------------
// AddrSpec – parsed destination address
// -----------------------------------------------------------------------

// AddrSpec describes the target address sent by the SOCKS5 client.
type AddrSpec struct {
	FQDN string   // set when the client sent a domain name
	IP   net.IP   // set for IPv4/IPv6, or resolved from FQDN
	Port int
}

func (a AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s:%d", a.FQDN, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// address returns the host:port string suitable for net.Dial.
func (a AddrSpec) address() string {
	host := a.FQDN
	if host == "" {
		host = a.IP.String()
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", a.Port))
}

// -----------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------

// Server is a SOCKS5 proxy server.
type Server struct {
	cfg Config
}

// New creates a new Server with the given configuration.
func New(cfg Config) *Server {
	cfg.defaults()
	return &Server{cfg: cfg}
}

// ListenAndServe starts accepting connections on the given network/address.
// It blocks until the listener is closed or an unrecoverable error occurs.
func (s *Server) ListenAndServe(network, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s %s: %w", network, addr, err)
	}
	s.cfg.Logger.Printf("socks5: listening on %s", ln.Addr())
	return s.Serve(ln)
}

// Serve accepts and handles connections from the given listener.
func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A temporary error (e.g. "too many open files") → log and retry.
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() { //nolint:staticcheck
				s.cfg.Logger.Printf("socks5: temporary accept error: %v", err)
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// -----------------------------------------------------------------------
// Per-connection handling
// -----------------------------------------------------------------------

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	ctx := context.Background()

	// 1. Authenticate / negotiate auth method.
	if err := s.negotiate(conn); err != nil {
		s.cfg.Logger.Printf("socks5: auth from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// 2. Read and validate the client request.
	req, err := s.readRequest(conn)
	if err != nil {
		s.cfg.Logger.Printf("socks5: request from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// 3. Apply rules.
	if s.cfg.Rules != nil && !s.cfg.Rules(ctx, req.Dest) {
		s.cfg.Logger.Printf("socks5: blocked %s → %s", conn.RemoteAddr(), req.Dest)
		_ = sendReply(conn, repNotAllowed, AddrSpec{IP: net.IPv4zero, Port: 0})
		return
	}

	// 4. Handle the command (only CONNECT supported).
	if req.Command != cmdConnect {
		_ = sendReply(conn, repCmdNotSupported, AddrSpec{IP: net.IPv4zero, Port: 0})
		return
	}

	s.handleConnect(ctx, conn, req)
}

// -----------------------------------------------------------------------
// Step 1 – method negotiation (and optional user/pass sub-negotiation)
// -----------------------------------------------------------------------

func (s *Server) negotiate(conn net.Conn) error {
	// Read: VER | NMETHODS | METHODS…
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Choose method.
	if s.cfg.Credentials != nil {
		// Require password auth – check that client supports it.
		if !contains(methods, authPassword) {
			_, _ = conn.Write([]byte{socks5Version, authNoAccept})
			return errors.New("client does not support user/pass auth")
		}
		if _, err := conn.Write([]byte{socks5Version, authPassword}); err != nil {
			return err
		}
		return s.passwordSubNeg(conn)
	}

	// No auth.
	_, err := conn.Write([]byte{socks5Version, authNone})
	return err
}

// passwordSubNeg performs RFC-1929 username/password sub-negotiation.
func (s *Server) passwordSubNeg(conn net.Conn) error {
	// VER | ULEN | USERNAME | PLEN | PASSWORD
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("auth sub-neg header: %w", err)
	}
	if header[0] != authPasswordVersion {
		return fmt.Errorf("unsupported auth sub-version %d", header[0])
	}
	uLen := int(header[1])
	user := make([]byte, uLen)
	if _, err := io.ReadFull(conn, user); err != nil {
		return fmt.Errorf("auth read username: %w", err)
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return fmt.Errorf("auth read plen: %w", err)
	}
	pass := make([]byte, int(pLenBuf[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return fmt.Errorf("auth read password: %w", err)
	}

	if expected, ok := s.cfg.Credentials[string(user)]; ok && expected == string(pass) {
		_, err := conn.Write([]byte{authPasswordVersion, authSuccess})
		return err
	}
	_, _ = conn.Write([]byte{authPasswordVersion, authFailure})
	return errors.New("invalid credentials")
}

// -----------------------------------------------------------------------
// Step 2 – parse the CONNECT / BIND / ASSOCIATE request
// -----------------------------------------------------------------------

type request struct {
	Command uint8
	Dest    AddrSpec
}

func (s *Server) readRequest(conn net.Conn) (*request, error) {
	// VER | CMD | RSV | ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unexpected version %d in request", header[0])
	}

	dest, err := s.readAddr(conn, header[3])
	if err != nil {
		_ = sendReply(conn, repAddrNotSupported, AddrSpec{IP: net.IPv4zero})
		return nil, err
	}

	return &request{Command: header[1], Dest: dest}, nil
}

func (s *Server) readAddr(conn net.Conn, atyp byte) (AddrSpec, error) {
	var spec AddrSpec

	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return spec, fmt.Errorf("read IPv4: %w", err)
		}
		spec.IP = net.IP(ip)

	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return spec, fmt.Errorf("read IPv6: %w", err)
		}
		spec.IP = net.IP(ip)

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return spec, fmt.Errorf("read domain length: %w", err)
		}
		fqdn := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, fqdn); err != nil {
			return spec, fmt.Errorf("read domain: %w", err)
		}
		spec.FQDN = string(fqdn)

	default:
		return spec, fmt.Errorf("unsupported address type %d", atyp)
	}

	// Port (2 bytes, big-endian)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return spec, fmt.Errorf("read port: %w", err)
	}
	spec.Port = int(binary.BigEndian.Uint16(portBuf))
	return spec, nil
}

// -----------------------------------------------------------------------
// Step 3 – CONNECT handler
// -----------------------------------------------------------------------

func (s *Server) handleConnect(ctx context.Context, client net.Conn, req *request) {
	// Resolve FQDN if needed.
	target := req.Dest
	if target.FQDN != "" {
		addrs, err := s.cfg.Resolver.LookupHost(ctx, target.FQDN)
		if err != nil || len(addrs) == 0 {
			s.cfg.Logger.Printf("socks5: DNS %q: %v", target.FQDN, err)
			_ = sendReply(client, repHostUnreachable, AddrSpec{IP: net.IPv4zero})
			return
		}
		target.IP = net.ParseIP(addrs[0])
	}

	// Dial the upstream target.
	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", target.address())
	if err != nil {
		s.cfg.Logger.Printf("socks5: dial %s: %v", target, err)
		rep := dialErrToReply(err)
		_ = sendReply(client, rep, AddrSpec{IP: net.IPv4zero})
		return
	}
	defer upstream.Close()

	// Tell the client we're connected; report the local bound address.
	localAddr := upstream.LocalAddr().(*net.TCPAddr)
	bound := AddrSpec{IP: localAddr.IP, Port: localAddr.Port}
	if err := sendReply(client, repSuccess, bound); err != nil {
		s.cfg.Logger.Printf("socks5: send reply: %v", err)
		return
	}

	s.cfg.Logger.Printf("socks5: %s → %s", client.RemoteAddr(), target)

	// Bidirectional relay.
	relay(client, upstream)
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// sendReply writes a SOCKS5 reply to conn.
func sendReply(conn net.Conn, rep uint8, bound AddrSpec) error {
	// Build address part.
	var addrPart []byte
	if bound.IP.To4() != nil {
		addrPart = append([]byte{atypIPv4}, bound.IP.To4()...)
	} else if ip6 := bound.IP.To16(); ip6 != nil {
		addrPart = append([]byte{atypIPv6}, ip6...)
	} else {
		// fallback: IPv4 zero
		addrPart = []byte{atypIPv4, 0, 0, 0, 0}
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(bound.Port))

	msg := []byte{socks5Version, rep, 0x00}
	msg = append(msg, addrPart...)
	msg = append(msg, port...)

	_, err := conn.Write(msg)
	return err
}

// relay copies data bidirectionally between a and b until either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Signal the other direction to stop.
		_ = dst.SetDeadline(time.Now())
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// contains reports whether slice s contains v.
func contains(s []byte, v byte) bool {
	for _, b := range s {
		if b == v {
			return true
		}
	}
	return false
}

// dialErrToReply maps a net.Dial error to the closest SOCKS5 reply code.
func dialErrToReply(err error) uint8 {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch {
		case opErr.Timeout():
			return repHostUnreachable
		}
		if opErr.Err != nil {
			msg := opErr.Err.Error()
			switch {
			case contains([]byte(msg), 'r') && contains([]byte(msg), 'e') &&
				contains([]byte(msg), 'f'): // "connection refused"
				return repConnRefused
			}
		}
	}
	return repServerFailure
}
