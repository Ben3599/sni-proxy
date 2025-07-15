package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultHTTPListen  = ":80"
	defaultHTTPSListen = ":443"
	defaultHTTPPort    = "80"
	defaultHTTPSPort   = "443"
	maxHTTPHeaderSize  = 64 * 1024
	maxTLSHelloSize    = 128 * 1024
	maxTLSRecordSize   = 18 * 1024
)

var (
	errNoServerName = errors.New("server name was not found")
	errNeedMoreData = errors.New("more data is required")
)

type closeWriter interface {
	CloseWrite() error
}

func main() {
	httpListen := flag.String("http-listen", defaultHTTPListen, "HTTP listen address")
	httpsListen := flag.String("https-listen", defaultHTTPSListen, "HTTPS listen address")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	readTimeout := flag.Duration("read-timeout", 10*time.Second, "initial client read timeout")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	httpListener, err := net.Listen("tcp", *httpListen)
	if err != nil {
		log.Fatalf("Failed to listen on HTTP address %s: %v", *httpListen, err)
	}
	defer httpListener.Close()

	httpsListener, err := net.Listen("tcp", *httpsListen)
	if err != nil {
		log.Fatalf("Failed to listen on HTTPS address %s: %v", *httpsListen, err)
	}
	defer httpsListener.Close()

	errCh := make(chan error, 2)
	go serve(httpListener, "http", *dialTimeout, *readTimeout, handleHTTPConnection, errCh)
	go serve(httpsListener, "https", *dialTimeout, *readTimeout, handleHTTPSConnection, errCh)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("HTTP proxy is listening on %s", *httpListen)
	log.Printf("HTTPS proxy is listening on %s", *httpsListen)

	select {
	case sig := <-signalCh:
		log.Printf("Received signal %s, shutting down", sig)
	case err := <-errCh:
		log.Printf("Listener stopped: %v", err)
	}
}

func serve(
	listener net.Listener,
	protocol string,
	dialTimeout time.Duration,
	readTimeout time.Duration,
	handler func(net.Conn, time.Duration, time.Duration),
	errCh chan<- error,
) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("%s accept failed: %w", protocol, err)
			return
		}

		go handler(conn, dialTimeout, readTimeout)
	}
}

func handleHTTPConnection(client net.Conn, dialTimeout time.Duration, readTimeout time.Duration) {
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		log.Printf("Failed to set initial read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	initial, err := readHTTPInitialBytes(client, maxHTTPHeaderSize)
	if err != nil {
		log.Printf("Failed to read HTTP request from %s: %v", client.RemoteAddr(), err)
		return
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	authority, err := parseHTTPAuthority(initial)
	if err != nil {
		log.Printf("Failed to get HTTP host from %s: %v", client.RemoteAddr(), err)
		return
	}

	target, serverName, err := buildTargetAddress(authority, defaultHTTPPort)
	if err != nil {
		log.Printf("Invalid HTTP host from %s: %v", client.RemoteAddr(), err)
		return
	}

	log.Printf("HTTP request from %s is routed to %s", client.RemoteAddr(), target)
	proxyConnection(client, target, initial, serverName, dialTimeout)
}

func handleHTTPSConnection(client net.Conn, dialTimeout time.Duration, readTimeout time.Duration) {
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		log.Printf("Failed to set initial read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	serverName, initial, err := readTLSClientHello(client, maxTLSHelloSize)
	if err != nil {
		log.Printf("Failed to read TLS ClientHello from %s: %v", client.RemoteAddr(), err)
		return
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	target := net.JoinHostPort(serverName, defaultHTTPSPort)
	log.Printf("HTTPS request from %s is routed to %s", client.RemoteAddr(), target)
	proxyConnection(client, target, initial, serverName, dialTimeout)
}

func proxyConnection(client net.Conn, target string, initial []byte, serverName string, dialTimeout time.Duration) {
	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("Failed to connect to upstream %s for %s: %v", target, serverName, err)
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(initial); err != nil {
		log.Printf("Failed to write initial bytes to upstream %s: %v", target, err)
		return
	}

	pipeBidirectional(client, upstream)
}

func pipeBidirectional(left net.Conn, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(right, left)
		closeWrite(right)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(left, right)
		closeWrite(left)
	}()

	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}

	_ = conn.Close()
}

func readHTTPInitialBytes(conn net.Conn, maxSize int) ([]byte, error) {
	var data []byte
	buf := make([]byte, 4096)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if end := headerEnd(data); end >= 0 {
				if end > maxSize {
					return nil, fmt.Errorf("HTTP header is larger than %d bytes", maxSize)
				}
				return data, nil
			}
			if len(data) > maxSize {
				return nil, fmt.Errorf("HTTP header is larger than %d bytes", maxSize)
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

func headerEnd(data []byte) int {
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		return idx + 4
	}
	if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
		return idx + 2
	}
	return -1
}

func parseHTTPAuthority(initial []byte) (string, error) {
	end := headerEnd(initial)
	if end < 0 {
		return "", errors.New("HTTP header terminator was not found")
	}

	header := string(initial[:end])
	lines := strings.Split(header, "\n")
	if len(lines) == 0 {
		return "", errors.New("HTTP request line was not found")
	}

	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "host") {
			value = strings.TrimSpace(value)
			if value == "" {
				return "", errors.New("HTTP Host header is empty")
			}
			return value, nil
		}
	}

	fields := strings.Fields(strings.TrimRight(lines[0], "\r"))
	if len(fields) < 2 {
		return "", errors.New("HTTP request line is invalid")
	}

	requestURL, err := url.Parse(fields[1])
	if err == nil && requestURL.Host != "" {
		return requestURL.Host, nil
	}

	return "", errNoServerName
}

func buildTargetAddress(authority string, defaultPort string) (target string, serverName string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", errors.New("authority is empty")
	}

	if strings.HasPrefix(authority, "//") {
		requestURL, parseErr := url.Parse(authority)
		if parseErr == nil && requestURL.Host != "" {
			authority = requestURL.Host
		}
	}

	host := authority
	port := defaultPort

	if h, p, splitErr := net.SplitHostPort(authority); splitErr == nil {
		host = h
		port = p
	} else if strings.HasPrefix(authority, "[") {
		end := strings.LastIndex(authority, "]")
		if end < 0 {
			return "", "", fmt.Errorf("IPv6 host is missing closing bracket: %s", authority)
		}
		host = authority[1:end]
		if len(authority) > end+1 {
			return "", "", fmt.Errorf("IPv6 host has invalid port syntax: %s", authority)
		}
	} else if strings.Count(authority, ":") == 1 {
		parts := strings.SplitN(authority, ":", 2)
		host = parts[0]
		port = parts[1]
	}

	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return "", "", errors.New("host is empty")
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if port == "" {
		return "", "", errors.New("port is empty")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", "", fmt.Errorf("port is invalid: %s", port)
	}

	host = strings.ToLower(host)
	return net.JoinHostPort(host, port), host, nil
}

func readTLSClientHello(conn net.Conn, maxHelloSize int) (string, []byte, error) {
	var initial bytes.Buffer
	handshake := make([]byte, 0, 4096)

	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return "", nil, err
		}
		initial.Write(header)

		recordType := header[0]
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength <= 0 || recordLength > maxTLSRecordSize {
			return "", nil, fmt.Errorf("invalid TLS record length: %d", recordLength)
		}
		if initial.Len()+recordLength > maxHelloSize {
			return "", nil, fmt.Errorf("TLS ClientHello is larger than %d bytes", maxHelloSize)
		}

		body := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", nil, err
		}
		initial.Write(body)

		if recordType != 22 {
			return "", nil, fmt.Errorf("expected TLS handshake record, got type %d", recordType)
		}

		handshake = append(handshake, body...)
		serverName, err := parseTLSClientHelloSNI(handshake)
		if err == nil {
			return serverName, initial.Bytes(), nil
		}
		if !errors.Is(err, errNeedMoreData) {
			return "", nil, err
		}
	}
}

func parseTLSClientHelloSNI(data []byte) (string, error) {
	if len(data) < 4 {
		return "", errNeedMoreData
	}
	if data[0] != 1 {
		return "", fmt.Errorf("expected ClientHello handshake, got type %d", data[0])
	}

	messageLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+messageLength {
		return "", errNeedMoreData
	}

	body := data[4 : 4+messageLength]
	return parseClientHelloBodySNI(body)
}

func parseClientHelloBodySNI(body []byte) (string, error) {
	offset := 0

	if len(body) < offset+2+32 {
		return "", errors.New("ClientHello is missing version or random bytes")
	}
	offset += 2 + 32

	if len(body) < offset+1 {
		return "", errors.New("ClientHello is missing session ID length")
	}
	sessionIDLength := int(body[offset])
	offset++
	if len(body) < offset+sessionIDLength {
		return "", errors.New("ClientHello session ID is truncated")
	}
	offset += sessionIDLength

	if len(body) < offset+2 {
		return "", errors.New("ClientHello is missing cipher suite length")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if cipherSuitesLength%2 != 0 {
		return "", errors.New("ClientHello cipher suite length is invalid")
	}
	if len(body) < offset+cipherSuitesLength {
		return "", errors.New("ClientHello cipher suites are truncated")
	}
	offset += cipherSuitesLength

	if len(body) < offset+1 {
		return "", errors.New("ClientHello is missing compression method length")
	}
	compressionMethodsLength := int(body[offset])
	offset++
	if len(body) < offset+compressionMethodsLength {
		return "", errors.New("ClientHello compression methods are truncated")
	}
	offset += compressionMethodsLength

	if len(body) == offset {
		return "", errNoServerName
	}
	if len(body) < offset+2 {
		return "", errors.New("ClientHello is missing extension length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+extensionsLength {
		return "", errors.New("ClientHello extensions are truncated")
	}

	extensions := body[offset : offset+extensionsLength]
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return "", errors.New("ClientHello extension header is truncated")
		}

		extensionType := binary.BigEndian.Uint16(extensions[0:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extensionLength {
			return "", errors.New("ClientHello extension data is truncated")
		}

		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]

		if extensionType != 0 {
			continue
		}

		return parseServerNameExtension(extensionData)
	}

	return "", errNoServerName
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("SNI extension is missing name list length")
	}

	listLength := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLength {
		return "", errors.New("SNI name list is truncated")
	}

	names := data[2 : 2+listLength]
	for len(names) > 0 {
		if len(names) < 3 {
			return "", errors.New("SNI name item is truncated")
		}

		nameType := names[0]
		nameLength := int(binary.BigEndian.Uint16(names[1:3]))
		names = names[3:]
		if len(names) < nameLength {
			return "", errors.New("SNI host name is truncated")
		}

		name := string(names[:nameLength])
		names = names[nameLength:]
		if nameType == 0 && name != "" {
			return strings.ToLower(name), nil
		}
	}

	return "", errNoServerName
}
