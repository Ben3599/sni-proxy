package main

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
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

func TestParseYAMLConfigReadsLogLevelAndHosts(t *testing.T) {
	cfg, err := parseYAMLConfig([]byte("# Test configuration\nlog_level: \"debug\" # request logs\nclient_whitelist:\n  - 192.0.2.10\n  - 198.51.100.0/24\n  - \"2001:db8::/64\"\ndomain_whitelist:\n  - Example.COM.\n  - ipv6.example.com\nhosts:\n  Example.COM.: 203.0.113.10\n  ipv6.example.com: \"2001:db8::10\"\nip_family:\n  Example.COM.: ipv4\n  ipv6.example.com: ipv6\noutbound_ip:\n  Example.COM.: 198.51.100.20\n  ipv6.example.com: \"2001:db8::20\"\n  range.example.com: 198.51.100.20/24\n"))
	if err != nil {
		t.Fatalf("parseYAMLConfig returned an error: %v", err)
	}
	if cfg.LogLevel != levelDebug {
		t.Fatalf("LogLevel = %v, want %v", cfg.LogLevel, levelDebug)
	}
	if len(cfg.ClientWhitelist) != 3 {
		t.Fatalf("len(ClientWhitelist) = %d, want %d", len(cfg.ClientWhitelist), 3)
	}
	if cfg.ClientWhitelist[0].String() != "192.0.2.10/32" {
		t.Fatalf("ClientWhitelist[0] = %q, want %q", cfg.ClientWhitelist[0], "192.0.2.10/32")
	}
	if cfg.ClientWhitelist[1].String() != "198.51.100.0/24" {
		t.Fatalf("ClientWhitelist[1] = %q, want %q", cfg.ClientWhitelist[1], "198.51.100.0/24")
	}
	if cfg.ClientWhitelist[2].String() != "2001:db8::/64" {
		t.Fatalf("ClientWhitelist[2] = %q, want %q", cfg.ClientWhitelist[2], "2001:db8::/64")
	}
	if _, ok := cfg.DomainWhitelist["example.com"]; !ok {
		t.Fatal("DomainWhitelist[example.com] is missing")
	}
	if _, ok := cfg.DomainWhitelist["ipv6.example.com"]; !ok {
		t.Fatal("DomainWhitelist[ipv6.example.com] is missing")
	}
	if cfg.Hosts["example.com"] != "203.0.113.10" {
		t.Fatalf("Hosts[example.com] = %q, want %q", cfg.Hosts["example.com"], "203.0.113.10")
	}
	if cfg.Hosts["ipv6.example.com"] != "2001:db8::10" {
		t.Fatalf("Hosts[ipv6.example.com] = %q, want %q", cfg.Hosts["ipv6.example.com"], "2001:db8::10")
	}
	if cfg.IPFamilies["example.com"] != familyIPv4 {
		t.Fatalf("IPFamilies[example.com] = %v, want %v", cfg.IPFamilies["example.com"], familyIPv4)
	}
	if cfg.IPFamilies["ipv6.example.com"] != familyIPv6 {
		t.Fatalf("IPFamilies[ipv6.example.com] = %v, want %v", cfg.IPFamilies["ipv6.example.com"], familyIPv6)
	}
	if cfg.OutboundIP["example.com"].Value != "198.51.100.20" {
		t.Fatalf("OutboundIP[example.com] = %q, want %q", cfg.OutboundIP["example.com"].Value, "198.51.100.20")
	}
	if cfg.OutboundIP["ipv6.example.com"].Value != "2001:db8::20" {
		t.Fatalf("OutboundIP[ipv6.example.com] = %q, want %q", cfg.OutboundIP["ipv6.example.com"].Value, "2001:db8::20")
	}
	if cfg.OutboundIP["range.example.com"].Value != "198.51.100.0/24" {
		t.Fatalf("OutboundIP[range.example.com] = %q, want %q", cfg.OutboundIP["range.example.com"].Value, "198.51.100.0/24")
	}
}

func TestParseYAMLConfigRejectsUnsupportedKeys(t *testing.T) {
	_, err := parseYAMLConfig([]byte("log_level: info\nlisten: :8080\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "unsupported configuration key") {
		t.Fatalf("error = %q, want unsupported key error", err.Error())
	}
}

func TestParseYAMLConfigRejectsNonIPHostsValue(t *testing.T) {
	_, err := parseYAMLConfig([]byte("hosts:\n  example.com: upstream.example.net\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "must be an IP address") {
		t.Fatalf("error = %q, want IP address error", err.Error())
	}
}

func TestParseYAMLConfigRejectsInvalidIPFamily(t *testing.T) {
	_, err := parseYAMLConfig([]byte("ip_family:\n  example.com: auto\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "supported values are ipv4 and ipv6") {
		t.Fatalf("error = %q, want supported values error", err.Error())
	}
}

func TestParseYAMLConfigRejectsHostsAndIPFamilyMismatch(t *testing.T) {
	_, err := parseYAMLConfig([]byte("hosts:\n  example.com: 203.0.113.10\nip_family:\n  example.com: ipv6\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "conflicts with ip_family") {
		t.Fatalf("error = %q, want conflict error", err.Error())
	}
}

func TestParseYAMLConfigRejectsInvalidOutboundIP(t *testing.T) {
	_, err := parseYAMLConfig([]byte("outbound_ip:\n  example.com: local.example.net\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "must be an IP address or CIDR prefix") {
		t.Fatalf("error = %q, want IP address or CIDR prefix error", err.Error())
	}
}

func TestParseYAMLConfigRejectsInvalidClientWhitelistItem(t *testing.T) {
	_, err := parseYAMLConfig([]byte("client_whitelist:\n  - local.example.net\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "must be an IP address or CIDR prefix") {
		t.Fatalf("error = %q, want IP address or CIDR prefix error", err.Error())
	}
}

func TestParseYAMLConfigRejectsClientWhitelistMappingItem(t *testing.T) {
	_, err := parseYAMLConfig([]byte("client_whitelist:\n  192.0.2.10: true\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "invalid client_whitelist item") {
		t.Fatalf("error = %q, want invalid item error", err.Error())
	}
}

func TestParseYAMLConfigRejectsInvalidDomainWhitelistItem(t *testing.T) {
	_, err := parseYAMLConfig([]byte("domain_whitelist:\n  - example.com:443\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "host must not include a port") {
		t.Fatalf("error = %q, want port error", err.Error())
	}
}

func TestParseYAMLConfigRejectsDomainWhitelistMappingItem(t *testing.T) {
	_, err := parseYAMLConfig([]byte("domain_whitelist:\n  example.com: true\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "invalid domain_whitelist item") {
		t.Fatalf("error = %q, want invalid item error", err.Error())
	}
}

func TestParseYAMLConfigRejectsOutboundIPAndIPFamilyMismatch(t *testing.T) {
	_, err := parseYAMLConfig([]byte("ip_family:\n  example.com: ipv6\noutbound_ip:\n  example.com: 198.51.100.20\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "conflicts with ip_family") {
		t.Fatalf("error = %q, want conflict error", err.Error())
	}
}

func TestParseYAMLConfigRejectsHostsAndOutboundIPMismatch(t *testing.T) {
	_, err := parseYAMLConfig([]byte("hosts:\n  example.com: 203.0.113.10\noutbound_ip:\n  example.com: 2001:db8::20\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "conflicts with outbound_ip") {
		t.Fatalf("error = %q, want conflict error", err.Error())
	}
}

func TestResolveRouteTargetUsesHostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:8443",
		"example.com",
		config{
			Hosts:      map[string]string{"example.com": "203.0.113.10"},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if !route.HostsOverridden {
		t.Fatal("HostsOverridden = false, want true")
	}
	if route.DialTarget != "203.0.113.10:8443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "203.0.113.10:8443")
	}
	if route.Network != "tcp" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp")
	}
}

func TestResolveRouteTargetSupportsIPv6HostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"ipv6.example.com:443",
		"ipv6.example.com",
		config{
			Hosts:      map[string]string{"ipv6.example.com": "2001:db8::10"},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if !route.HostsOverridden {
		t.Fatal("HostsOverridden = false, want true")
	}
	if route.DialTarget != "[2001:db8::10]:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "[2001:db8::10]:443")
	}
}

func TestResolveRouteTargetKeepsOriginalWhenHostIsMissing(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:443",
		"example.com",
		config{
			Hosts:      map[string]string{"other.example.com": "203.0.113.10"},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.HostsOverridden {
		t.Fatal("HostsOverridden = true, want false")
	}
	if route.DialTarget != "example.com:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "example.com:443")
	}
}

func TestResolveRouteTargetUsesForcedIPv4(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:443",
		"Example.COM.",
		config{
			Hosts:      map[string]string{},
			IPFamilies: map[string]ipFamily{"example.com": familyIPv4},
			OutboundIP: map[string]outboundSource{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp4" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp4")
	}
	if route.DialTarget != "example.com:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "example.com:443")
	}
}

func TestResolveRouteTargetUsesForcedIPv6WithHostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"ipv6.example.com:443",
		"ipv6.example.com",
		config{
			Hosts:      map[string]string{"ipv6.example.com": "2001:db8::10"},
			IPFamilies: map[string]ipFamily{"ipv6.example.com": familyIPv6},
			OutboundIP: map[string]outboundSource{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp6" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp6")
	}
	if route.DialTarget != "[2001:db8::10]:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "[2001:db8::10]:443")
	}
}

func TestResolveRouteTargetUsesOutboundIPv4(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:443",
		"Example.COM.",
		config{
			Hosts:      map[string]string{},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{"example.com": mustOutboundSource(t, "198.51.100.20")},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp4" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp4")
	}
	if route.OutboundIP != "198.51.100.20" {
		t.Fatalf("OutboundIP = %q, want %q", route.OutboundIP, "198.51.100.20")
	}
	if route.DialTarget != "example.com:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "example.com:443")
	}
}

func TestResolveRouteTargetUsesOutboundIPv6WithHostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"ipv6.example.com:443",
		"ipv6.example.com",
		config{
			Hosts:      map[string]string{"ipv6.example.com": "2001:db8::10"},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{"ipv6.example.com": mustOutboundSource(t, "2001:db8::20")},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp6" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp6")
	}
	if route.DialTarget != "[2001:db8::10]:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "[2001:db8::10]:443")
	}
	if route.OutboundIP != "2001:db8::20" {
		t.Fatalf("OutboundIP = %q, want %q", route.OutboundIP, "2001:db8::20")
	}
}

func TestResolveRouteTargetUsesRandomIPv4FromOutboundPrefix(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:443",
		"example.com",
		config{
			Hosts:      map[string]string{},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{"example.com": mustOutboundSource(t, "198.51.100.0/30")},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp4" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp4")
	}
	if route.OutboundIP != "198.51.100.1" && route.OutboundIP != "198.51.100.2" {
		t.Fatalf("OutboundIP = %q, want usable IP from 198.51.100.0/30", route.OutboundIP)
	}
}

func TestResolveRouteTargetUsesRandomIPv6FromOutboundPrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/126")
	route, err := resolveRouteTarget(
		"ipv6.example.com:443",
		"ipv6.example.com",
		config{
			Hosts:      map[string]string{},
			IPFamilies: map[string]ipFamily{},
			OutboundIP: map[string]outboundSource{"ipv6.example.com": mustOutboundSource(t, prefix.String())},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp6" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp6")
	}

	addr := netip.MustParseAddr(route.OutboundIP)
	if !prefix.Contains(addr) {
		t.Fatalf("OutboundIP = %q, want IP from %s", route.OutboundIP, prefix)
	}
}

func TestRandomAddressFromIPv4PrefixSkipsNetworkAndBroadcast(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/30")

	for i := 0; i < 20; i++ {
		addr, err := randomAddressFromPrefix(prefix)
		if err != nil {
			t.Fatalf("randomAddressFromPrefix returned an error: %v", err)
		}
		if addr.String() == "198.51.100.0" || addr.String() == "198.51.100.3" {
			t.Fatalf("addr = %q, want usable host address", addr)
		}
		if !prefix.Contains(addr) {
			t.Fatalf("addr = %q, want address from %s", addr, prefix)
		}
	}
}

func TestClientAllowedAllowsAllWhenWhitelistIsEmpty(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345}

	if !clientAllowed(remoteAddr, nil) {
		t.Fatal("clientAllowed = false, want true")
	}
}

func TestClientAllowedMatchesSingleIPv4(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}
	whitelist := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}

	if !clientAllowed(remoteAddr, whitelist) {
		t.Fatal("clientAllowed = false, want true")
	}
}

func TestClientAllowedMatchesIPv4CIDR(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.42"), Port: 12345}
	whitelist := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}

	if !clientAllowed(remoteAddr, whitelist) {
		t.Fatal("clientAllowed = false, want true")
	}
}

func TestClientAllowedMatchesIPv6CIDR(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("2001:db8::42"), Port: 12345}
	whitelist := []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}

	if !clientAllowed(remoteAddr, whitelist) {
		t.Fatal("clientAllowed = false, want true")
	}
}

func TestClientAllowedRejectsMissingIP(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345}
	whitelist := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}

	if clientAllowed(remoteAddr, whitelist) {
		t.Fatal("clientAllowed = true, want false")
	}
}

func TestDomainAllowedAllowsAllWhenWhitelistIsEmpty(t *testing.T) {
	if !domainAllowed("blocked.example.com", nil) {
		t.Fatal("domainAllowed = false, want true")
	}
}

func TestDomainAllowedMatchesNormalizedDomain(t *testing.T) {
	whitelist := map[string]struct{}{"example.com": {}}

	if !domainAllowed("Example.COM.", whitelist) {
		t.Fatal("domainAllowed = false, want true")
	}
}

func TestDomainAllowedRejectsMissingDomain(t *testing.T) {
	whitelist := map[string]struct{}{"example.com": {}}

	if domainAllowed("other.example.com", whitelist) {
		t.Fatal("domainAllowed = true, want false")
	}
}

func TestLocalTCPAddrUsesSourceIP(t *testing.T) {
	addr, err := localTCPAddr("198.51.100.20")
	if err != nil {
		t.Fatalf("localTCPAddr returned an error: %v", err)
	}
	if addr == nil {
		t.Fatal("addr = nil, want TCP address")
	}
	if addr.IP.String() != "198.51.100.20" {
		t.Fatalf("addr.IP = %q, want %q", addr.IP.String(), "198.51.100.20")
	}
}

func mustOutboundSource(t *testing.T, value string) outboundSource {
	t.Helper()

	source, err := parseOutboundSource(value)
	if err != nil {
		t.Fatalf("parseOutboundSource returned an error: %v", err)
	}
	return source
}
