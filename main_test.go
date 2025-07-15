package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestParseHTTPAuthorityUsesHostHeader(t *testing.T) {
	initial := []byte("GET / HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent: test\r\n\r\n")

	authority, err := parseHTTPAuthority(initial)
	if err != nil {
		t.Fatalf("parseHTTPAuthority returned an error: %v", err)
	}
	if authority != "Example.COM:8080" {
		t.Fatalf("authority = %q, want %q", authority, "Example.COM:8080")
	}

	target, serverName, err := buildTargetAddress(authority, defaultHTTPPort)
	if err != nil {
		t.Fatalf("buildTargetAddress returned an error: %v", err)
	}
	if target != "example.com:8080" {
		t.Fatalf("target = %q, want %q", target, "example.com:8080")
	}
	if serverName != "example.com" {
		t.Fatalf("serverName = %q, want %q", serverName, "example.com")
	}
}

func TestParseHTTPAuthorityUsesAbsoluteURL(t *testing.T) {
	initial := []byte("GET http://example.org/path HTTP/1.0\r\nUser-Agent: test\r\n\r\n")

	authority, err := parseHTTPAuthority(initial)
	if err != nil {
		t.Fatalf("parseHTTPAuthority returned an error: %v", err)
	}
	if authority != "example.org" {
		t.Fatalf("authority = %q, want %q", authority, "example.org")
	}
}

func TestReadTLSClientHelloExtractsSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(clientConn, &tls.Config{
			ServerName:         "Example.COM",
			InsecureSkipVerify: true,
		})
		done <- tlsClient.Handshake()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned an error: %v", err)
	}

	serverName, initial, err := readTLSClientHello(serverConn, maxTLSHelloSize)
	if err != nil {
		t.Fatalf("readTLSClientHello returned an error: %v", err)
	}
	if serverName != "example.com" {
		t.Fatalf("serverName = %q, want %q", serverName, "example.com")
	}
	if len(initial) == 0 {
		t.Fatal("initial bytes are empty")
	}

	_ = serverConn.Close()
	<-done
}
