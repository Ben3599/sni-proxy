package main

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
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
	defaultConfigPath  = "config.yaml"
	defaultLogLevel    = "info"
	defaultHTTPPort    = "80"
	defaultHTTPSPort   = "443"
	maxHTTPHeaderSize  = 64 * 1024
	maxTLSHelloSize    = 128 * 1024
	maxTLSRecordSize   = 18 * 1024
)

type logLevel int
type ipFamily int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

const (
	familyAny ipFamily = iota
	familyIPv4
	familyIPv6
)

var (
	errNoServerName = errors.New("server name was not found")
	errNeedMoreData = errors.New("more data is required")
	appConfig       = defaultConfig()
	appLog          = leveledLogger{level: levelInfo}
)

type closeWriter interface {
	CloseWrite() error
}

type config struct {
	LogLevel        logLevel
	ClientWhitelist []netip.Prefix
	DomainWhitelist map[string]struct{}
	Hosts           map[string]string
	IPFamilies      map[string]ipFamily
	OutboundIP      map[string]outboundSource
}

type leveledLogger struct {
	level logLevel
}

type routeTarget struct {
	Target          string
	DialTarget      string
	Network         string
	HostsOverridden bool
	IPFamily        ipFamily
	OutboundIP      string
}

type outboundSource struct {
	Value  string
	Prefix netip.Prefix
	Family ipFamily
}

func (l leveledLogger) Debugf(format string, args ...any) {
	if l.level <= levelDebug {
		log.Printf("DEBUG "+format, args...)
	}
}

func (l leveledLogger) Infof(format string, args ...any) {
	if l.level <= levelInfo {
		log.Printf("INFO "+format, args...)
	}
}

func (l leveledLogger) Warnf(format string, args ...any) {
	if l.level <= levelWarn {
		log.Printf("WARN "+format, args...)
	}
}

func (l leveledLogger) Errorf(format string, args ...any) {
	if l.level <= levelError {
		log.Printf("ERROR "+format, args...)
	}
}

func main() {
	httpListen := flag.String("http-listen", defaultHTTPListen, "HTTP listen address")
	httpsListen := flag.String("https-listen", defaultHTTPSListen, "HTTPS listen address")
	configPath := flag.String("config", defaultConfigPath, "YAML configuration file path")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	readTimeout := flag.Duration("read-timeout", 10*time.Second, "initial client read timeout")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := loadConfig(*configPath, wasFlagSet("config"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	appLog = leveledLogger{level: cfg.LogLevel}
	appConfig = cfg

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

	appLog.Infof("HTTP proxy is listening on %s", *httpListen)
	appLog.Infof("HTTPS proxy is listening on %s", *httpsListen)

	select {
	case sig := <-signalCh:
		appLog.Infof("Received signal %s, shutting down", sig)
	case err := <-errCh:
		appLog.Errorf("Listener stopped: %v", err)
	}
}

func wasFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func defaultConfig() config {
	level, err := parseLogLevel(defaultLogLevel)
	if err != nil {
		panic(err)
	}
	return config{
		LogLevel:        level,
		ClientWhitelist: nil,
		DomainWhitelist: map[string]struct{}{},
		Hosts:           map[string]string{},
		IPFamilies:      map[string]ipFamily{},
		OutboundIP:      map[string]outboundSource{},
	}
}

func loadConfig(path string, required bool) (config, error) {
	cfg := defaultConfig()
	if path == "" {
		if required {
			return cfg, errors.New("configuration file path is empty")
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return cfg, nil
		}
		return cfg, err
	}

	if strings.TrimSpace(string(data)) == "" {
		return cfg, nil
	}

	return parseYAMLConfig(data)
}

func parseYAMLConfig(data []byte) (config, error) {
	cfg := defaultConfig()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 64*1024)

	lineNumber := 0
	section := ""
	for scanner.Scan() {
		lineNumber++
		line := stripYAMLComment(scanner.Text())
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || trimmedLine == "---" || trimmedLine == "..." {
			continue
		}

		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		if section != "" {
			if indented {
				switch section {
				case "hosts":
					if err := parseHostMappingLine(cfg.Hosts, trimmedLine, lineNumber); err != nil {
						return cfg, err
					}
				case "ip_family":
					if err := parseIPFamilyMappingLine(cfg.IPFamilies, trimmedLine, lineNumber); err != nil {
						return cfg, err
					}
				case "outbound_ip":
					if err := parseOutboundIPMappingLine(cfg.OutboundIP, trimmedLine, lineNumber); err != nil {
						return cfg, err
					}
				case "client_whitelist":
					if err := parseClientWhitelistLine(&cfg.ClientWhitelist, trimmedLine, lineNumber); err != nil {
						return cfg, err
					}
				case "domain_whitelist":
					if err := parseDomainWhitelistLine(cfg.DomainWhitelist, trimmedLine, lineNumber); err != nil {
						return cfg, err
					}
				default:
					return cfg, fmt.Errorf("unsupported configuration section %q on line %d", section, lineNumber)
				}
				continue
			}
			section = ""
		}
		if indented {
			return cfg, fmt.Errorf("unexpected indentation on line %d", lineNumber)
		}

		key, value, ok := strings.Cut(trimmedLine, ":")
		if !ok {
			return cfg, fmt.Errorf("invalid YAML line %d", lineNumber)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		var err error
		switch key {
		case "log_level":
			if value == "" {
				return cfg, fmt.Errorf("missing value for %q on line %d", key, lineNumber)
			}
			cfg.LogLevel, err = parseLogLevel(unquoteYAMLScalar(value))
		case "hosts":
			if value != "" {
				return cfg, fmt.Errorf("%q must be a mapping on line %d", key, lineNumber)
			}
			section = "hosts"
		case "ip_family":
			if value != "" {
				return cfg, fmt.Errorf("%q must be a mapping on line %d", key, lineNumber)
			}
			section = "ip_family"
		case "outbound_ip":
			if value != "" {
				return cfg, fmt.Errorf("%q must be a mapping on line %d", key, lineNumber)
			}
			section = "outbound_ip"
		case "client_whitelist":
			if value != "" {
				return cfg, fmt.Errorf("%q must be a list on line %d", key, lineNumber)
			}
			section = "client_whitelist"
		case "domain_whitelist":
			if value != "" {
				return cfg, fmt.Errorf("%q must be a list on line %d", key, lineNumber)
			}
			section = "domain_whitelist"
		default:
			return cfg, fmt.Errorf("unsupported configuration key %q on line %d", key, lineNumber)
		}
		if err != nil {
			return cfg, fmt.Errorf("invalid value for %q on line %d: %w", key, lineNumber, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return cfg, err
	}
	if err := validateConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseHostMappingLine(hosts map[string]string, line string, lineNumber int) error {
	host, address, ok := strings.Cut(line, ":")
	if !ok {
		return fmt.Errorf("invalid hosts mapping on line %d", lineNumber)
	}

	host, err := normalizeHostName(unquoteYAMLScalar(strings.TrimSpace(host)))
	if err != nil {
		return fmt.Errorf("invalid hosts key on line %d: %w", lineNumber, err)
	}

	address = unquoteYAMLScalar(strings.TrimSpace(address))
	if address == "" {
		return fmt.Errorf("missing hosts value for %q on line %d", host, lineNumber)
	}

	ip, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid hosts value for %q on line %d: must be an IP address", host, lineNumber)
	}

	hosts[host] = ip.String()
	return nil
}

func parseIPFamilyMappingLine(families map[string]ipFamily, line string, lineNumber int) error {
	host, value, ok := strings.Cut(line, ":")
	if !ok {
		return fmt.Errorf("invalid ip_family mapping on line %d", lineNumber)
	}

	host, err := normalizeHostName(unquoteYAMLScalar(strings.TrimSpace(host)))
	if err != nil {
		return fmt.Errorf("invalid ip_family key on line %d: %w", lineNumber, err)
	}

	value = unquoteYAMLScalar(strings.TrimSpace(value))
	if value == "" {
		return fmt.Errorf("missing ip_family value for %q on line %d", host, lineNumber)
	}

	family, err := parseIPFamily(value)
	if err != nil {
		return fmt.Errorf("invalid ip_family value for %q on line %d: %w", host, lineNumber, err)
	}

	families[host] = family
	return nil
}

func parseOutboundIPMappingLine(outboundIP map[string]outboundSource, line string, lineNumber int) error {
	host, address, ok := strings.Cut(line, ":")
	if !ok {
		return fmt.Errorf("invalid outbound_ip mapping on line %d", lineNumber)
	}

	host, err := normalizeHostName(unquoteYAMLScalar(strings.TrimSpace(host)))
	if err != nil {
		return fmt.Errorf("invalid outbound_ip key on line %d: %w", lineNumber, err)
	}

	address = unquoteYAMLScalar(strings.TrimSpace(address))
	if address == "" {
		return fmt.Errorf("missing outbound_ip value for %q on line %d", host, lineNumber)
	}

	source, err := parseOutboundSource(address)
	if err != nil {
		return fmt.Errorf("invalid outbound_ip value for %q on line %d: %w", host, lineNumber, err)
	}

	outboundIP[host] = source
	return nil
}

func parseClientWhitelistLine(whitelist *[]netip.Prefix, line string, lineNumber int) error {
	value, err := parseYAMLListItem(line, "client_whitelist", lineNumber)
	if err != nil {
		return err
	}

	prefix, err := parseIPOrPrefix(value)
	if err != nil {
		return fmt.Errorf("invalid client_whitelist value on line %d: %w", lineNumber, err)
	}

	*whitelist = append(*whitelist, prefix)
	return nil
}

func parseDomainWhitelistLine(whitelist map[string]struct{}, line string, lineNumber int) error {
	value, err := parseYAMLListItem(line, "domain_whitelist", lineNumber)
	if err != nil {
		return err
	}

	domain, err := normalizeHostName(value)
	if err != nil {
		return fmt.Errorf("invalid domain_whitelist value on line %d: %w", lineNumber, err)
	}

	whitelist[domain] = struct{}{}
	return nil
}

func parseYAMLListItem(line string, section string, lineNumber int) (string, error) {
	if !strings.HasPrefix(line, "-") {
		return "", fmt.Errorf("invalid %s item on line %d", section, lineNumber)
	}

	value := strings.TrimSpace(strings.TrimPrefix(line, "-"))
	if value == "" {
		return "", fmt.Errorf("missing %s value on line %d", section, lineNumber)
	}

	return unquoteYAMLScalar(value), nil
}

func validateConfig(cfg config) error {
	for host, family := range cfg.IPFamilies {
		address, ok := cfg.Hosts[host]
		if !ok {
			continue
		}
		if err := validateAddressFamily(address, family); err != nil {
			return fmt.Errorf("hosts value for %q conflicts with ip_family: %w", host, err)
		}
	}
	for host, source := range cfg.OutboundIP {
		if family, ok := cfg.IPFamilies[host]; ok && family != source.Family {
			return fmt.Errorf("outbound_ip value for %q conflicts with ip_family: source %s is not %s", host, source.Value, family)
		}
		if address, ok := cfg.Hosts[host]; ok {
			if err := validateAddressFamily(address, source.Family); err != nil {
				return fmt.Errorf("hosts value for %q conflicts with outbound_ip: %w", host, err)
			}
		}
	}
	return nil
}

func parseIPOrPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("must be an IP address or CIDR prefix")
		}
		return prefix.Masked(), nil
	}

	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("must be an IP address or CIDR prefix")
	}
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func parseOutboundSource(value string) (outboundSource, error) {
	if strings.Contains(value, "/") {
		prefix, err := parseIPOrPrefix(value)
		if err != nil {
			return outboundSource{}, err
		}
		family, err := addressFamily(prefix.Addr().String())
		if err != nil {
			return outboundSource{}, err
		}
		return outboundSource{
			Value:  prefix.String(),
			Prefix: prefix,
			Family: family,
		}, nil
	}

	ip, err := netip.ParseAddr(value)
	if err != nil {
		return outboundSource{}, fmt.Errorf("must be an IP address or CIDR prefix")
	}

	family, err := addressFamily(ip.String())
	if err != nil {
		return outboundSource{}, err
	}

	return outboundSource{
		Value:  ip.String(),
		Prefix: netip.PrefixFrom(ip, ip.BitLen()),
		Family: family,
	}, nil
}

func stripYAMLComment(line string) string {
	inSingleQuote := false
	inDoubleQuote := false

	for i, r := range line {
		switch r {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '#':
			if !inSingleQuote && !inDoubleQuote && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}

	return line
}

func unquoteYAMLScalar(value string) string {
	if len(value) < 2 {
		return value
	}

	if value[0] == '\'' && value[len(value)-1] == '\'' {
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'")
	}
	if value[0] == '"' && value[len(value)-1] == '"' {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}

	return value
}

func parseLogLevel(value string) (logLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return levelDebug, nil
	case "info":
		return levelInfo, nil
	case "warn", "warning":
		return levelWarn, nil
	case "error":
		return levelError, nil
	default:
		return levelInfo, fmt.Errorf("supported values are debug, info, warn, and error")
	}
}

func parseIPFamily(value string) (ipFamily, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ipv4", "ip4", "4":
		return familyIPv4, nil
	case "ipv6", "ip6", "6":
		return familyIPv6, nil
	default:
		return familyAny, fmt.Errorf("supported values are ipv4 and ipv6")
	}
}

func (f ipFamily) String() string {
	switch f {
	case familyIPv4:
		return "ipv4"
	case familyIPv6:
		return "ipv6"
	default:
		return "any"
	}
}

func (f ipFamily) network() string {
	switch f {
	case familyIPv4:
		return "tcp4"
	case familyIPv6:
		return "tcp6"
	default:
		return "tcp"
	}
}

func normalizeHostName(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" {
		return "", errors.New("host is empty")
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return "", fmt.Errorf("host contains invalid characters: %s", host)
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("host must not include a port: %s", host)
	}
	return host, nil
}

func normalizeLookupName(serverName string) string {
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if strings.HasSuffix(serverName, ".") {
		serverName = strings.TrimSuffix(serverName, ".")
	}
	return serverName
}

func resolveRouteTarget(target string, serverName string, cfg config) (routeTarget, error) {
	route := routeTarget{
		Target:     target,
		DialTarget: target,
		Network:    "tcp",
	}

	serverName = normalizeLookupName(serverName)
	if family, ok := cfg.IPFamilies[serverName]; ok {
		route.IPFamily = family
		route.Network = family.network()
	}
	if source, ok := cfg.OutboundIP[serverName]; ok {
		sourceIP, err := source.RandomIP()
		if err != nil {
			return route, err
		}
		if route.IPFamily != familyAny && route.IPFamily != source.Family {
			return route, fmt.Errorf("outbound IP %s does not match forced %s family", sourceIP, route.IPFamily)
		}
		if route.IPFamily == familyAny {
			route.IPFamily = source.Family
			route.Network = source.Family.network()
		}
		route.OutboundIP = sourceIP
	}

	address, ok := cfg.Hosts[serverName]
	if !ok {
		return route, nil
	}

	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return route, err
	}
	if err := validateAddressFamily(address, route.IPFamily); err != nil {
		return route, err
	}

	route.DialTarget = net.JoinHostPort(address, port)
	route.HostsOverridden = true
	return route, nil
}

func (s outboundSource) RandomIP() (string, error) {
	addr, err := randomAddressFromPrefix(s.Prefix)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func addressFamily(address string) (ipFamily, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return familyAny, err
	}
	if ip.Is4() {
		return familyIPv4, nil
	}
	if ip.Is6() {
		return familyIPv6, nil
	}
	return familyAny, fmt.Errorf("address %s is not ipv4 or ipv6", address)
}

func validateAddressFamily(address string, family ipFamily) error {
	if family == familyAny {
		return nil
	}

	ip, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}
	if family == familyIPv4 && !ip.Is4() {
		return fmt.Errorf("address %s is not ipv4", address)
	}
	if family == familyIPv6 && !ip.Is6() {
		return fmt.Errorf("address %s is not ipv6", address)
	}
	return nil
}

func randomAddressFromPrefix(prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.IsValid() {
		return netip.Addr{}, errors.New("prefix is invalid")
	}

	addr := prefix.Masked().Addr()
	bitLen := addr.BitLen()
	hostBits := bitLen - prefix.Bits()
	if hostBits < 0 {
		return netip.Addr{}, fmt.Errorf("prefix length is invalid: %s", prefix)
	}

	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	offset := new(big.Int)

	if addr.Is4() && hostBits >= 2 {
		usableSize := new(big.Int).Sub(size, big.NewInt(2))
		n, err := cryptorand.Int(cryptorand.Reader, usableSize)
		if err != nil {
			return netip.Addr{}, err
		}
		offset.Add(n, big.NewInt(1))
	} else {
		n, err := cryptorand.Int(cryptorand.Reader, size)
		if err != nil {
			return netip.Addr{}, err
		}
		offset = n
	}

	return addAddressOffset(addr, offset)
}

func addAddressOffset(addr netip.Addr, offset *big.Int) (netip.Addr, error) {
	var addrBytes []byte
	if addr.Is4() {
		a := addr.As4()
		addrBytes = a[:]
	} else {
		a := addr.As16()
		addrBytes = a[:]
	}

	base := new(big.Int).SetBytes(addrBytes)
	base.Add(base, offset)
	result := base.Bytes()
	if len(result) > len(addrBytes) {
		return netip.Addr{}, fmt.Errorf("address offset is out of range for %s", addr)
	}

	padded := make([]byte, len(addrBytes))
	copy(padded[len(padded)-len(result):], result)

	if addr.Is4() {
		var a [4]byte
		copy(a[:], padded)
		return netip.AddrFrom4(a), nil
	}

	var a [16]byte
	copy(a[:], padded)
	return netip.AddrFrom16(a), nil
}

func logRoute(protocol string, clientAddr net.Addr, route routeTarget) {
	if route.OutboundIP != "" && route.HostsOverridden && route.IPFamily != familyAny {
		appLog.Debugf("%s request from %s is routed to %s via hosts target %s using %s from source %s", protocol, clientAddr, route.Target, route.DialTarget, route.IPFamily, route.OutboundIP)
		return
	}
	if route.OutboundIP != "" && route.HostsOverridden {
		appLog.Debugf("%s request from %s is routed to %s via hosts target %s from source %s", protocol, clientAddr, route.Target, route.DialTarget, route.OutboundIP)
		return
	}
	if route.OutboundIP != "" && route.IPFamily != familyAny {
		appLog.Debugf("%s request from %s is routed to %s using %s from source %s", protocol, clientAddr, route.Target, route.IPFamily, route.OutboundIP)
		return
	}
	if route.OutboundIP != "" {
		appLog.Debugf("%s request from %s is routed to %s from source %s", protocol, clientAddr, route.Target, route.OutboundIP)
		return
	}
	if route.HostsOverridden && route.IPFamily != familyAny {
		appLog.Debugf("%s request from %s is routed to %s via hosts target %s using %s", protocol, clientAddr, route.Target, route.DialTarget, route.IPFamily)
		return
	}
	if route.HostsOverridden {
		appLog.Debugf("%s request from %s is routed to %s via hosts target %s", protocol, clientAddr, route.Target, route.DialTarget)
		return
	}
	if route.IPFamily != familyAny {
		appLog.Debugf("%s request from %s is routed to %s using %s", protocol, clientAddr, route.Target, route.IPFamily)
		return
	}
	appLog.Debugf("%s request from %s is routed to %s", protocol, clientAddr, route.Target)
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
		if !clientAllowed(conn.RemoteAddr(), appConfig.ClientWhitelist) {
			appLog.Warnf("Rejected connection from %s: source IP is not allowed", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}

		go handler(conn, dialTimeout, readTimeout)
	}
}

func clientAllowed(remoteAddr net.Addr, whitelist []netip.Prefix) bool {
	if len(whitelist) == 0 {
		return true
	}

	addr, err := remoteAddrIP(remoteAddr)
	if err != nil {
		appLog.Warnf("Rejected connection from %s: failed to parse source IP: %v", remoteAddr, err)
		return false
	}

	for _, prefix := range whitelist {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteAddrIP(remoteAddr net.Addr) (netip.Addr, error) {
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		addr, ok := netip.AddrFromSlice(tcpAddr.IP)
		if !ok {
			return netip.Addr{}, fmt.Errorf("invalid TCP source IP: %s", tcpAddr.IP)
		}
		return addr.Unmap(), nil
	}

	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}

func domainAllowed(serverName string, whitelist map[string]struct{}) bool {
	if len(whitelist) == 0 {
		return true
	}

	serverName = normalizeLookupName(serverName)
	_, ok := whitelist[serverName]
	return ok
}

func handleHTTPConnection(client net.Conn, dialTimeout time.Duration, readTimeout time.Duration) {
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		appLog.Errorf("Failed to set initial read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	initial, err := readHTTPInitialBytes(client, maxHTTPHeaderSize)
	if err != nil {
		appLog.Errorf("Failed to read HTTP request from %s: %v", client.RemoteAddr(), err)
		return
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		appLog.Errorf("Failed to clear read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	authority, err := parseHTTPAuthority(initial)
	if err != nil {
		appLog.Errorf("Failed to get HTTP host from %s: %v", client.RemoteAddr(), err)
		return
	}

	target, serverName, err := buildTargetAddress(authority, defaultHTTPPort)
	if err != nil {
		appLog.Errorf("Invalid HTTP host from %s: %v", client.RemoteAddr(), err)
		return
	}
	if !domainAllowed(serverName, appConfig.DomainWhitelist) {
		appLog.Warnf("Rejected HTTP request from %s: host %s is not allowed", client.RemoteAddr(), serverName)
		return
	}

	route, err := resolveRouteTarget(target, serverName, appConfig)
	if err != nil {
		appLog.Errorf("Failed to resolve HTTP target %s from %s: %v", target, client.RemoteAddr(), err)
		return
	}

	logRoute("HTTP", client.RemoteAddr(), route)
	proxyConnection(client, route, initial, serverName, dialTimeout)
}

func handleHTTPSConnection(client net.Conn, dialTimeout time.Duration, readTimeout time.Duration) {
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		appLog.Errorf("Failed to set initial read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	serverName, initial, err := readTLSClientHello(client, maxTLSHelloSize)
	if err != nil {
		appLog.Errorf("Failed to read TLS ClientHello from %s: %v", client.RemoteAddr(), err)
		return
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		appLog.Errorf("Failed to clear read deadline for %s: %v", client.RemoteAddr(), err)
		return
	}

	target := net.JoinHostPort(serverName, defaultHTTPSPort)
	if !domainAllowed(serverName, appConfig.DomainWhitelist) {
		appLog.Warnf("Rejected HTTPS request from %s: SNI %s is not allowed", client.RemoteAddr(), serverName)
		return
	}

	route, err := resolveRouteTarget(target, serverName, appConfig)
	if err != nil {
		appLog.Errorf("Failed to resolve HTTPS target %s from %s: %v", target, client.RemoteAddr(), err)
		return
	}

	logRoute("HTTPS", client.RemoteAddr(), route)
	proxyConnection(client, route, initial, serverName, dialTimeout)
}

func proxyConnection(client net.Conn, route routeTarget, initial []byte, serverName string, dialTimeout time.Duration) {
	localAddr, err := localTCPAddr(route.OutboundIP)
	if err != nil {
		appLog.Errorf("Failed to build outbound source address %s for %s: %v", route.OutboundIP, serverName, err)
		return
	}

	dialer := net.Dialer{
		Timeout:   dialTimeout,
		LocalAddr: localAddr,
	}
	upstream, err := dialer.Dial(route.Network, route.DialTarget)
	if err != nil {
		appLog.Errorf("Failed to connect to upstream %s over %s for %s: %v", route.DialTarget, route.Network, serverName, err)
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(initial); err != nil {
		appLog.Errorf("Failed to write initial bytes to upstream %s: %v", route.DialTarget, err)
		return
	}

	pipeBidirectional(client, upstream)
}

func localTCPAddr(sourceIP string) (*net.TCPAddr, error) {
	if sourceIP == "" {
		return nil, nil
	}

	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", sourceIP)
	}
	return &net.TCPAddr{IP: ip}, nil
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
