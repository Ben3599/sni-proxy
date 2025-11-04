# sni-proxy

`sni-proxy` is a small Go TCP proxy for HTTP and HTTPS virtual hosts.

- HTTP traffic on port `80` is routed by the `Host` header.
- HTTPS traffic on port `443` is routed by the SNI value from the TLS ClientHello.
- HTTPS traffic is not decrypted or terminated. The proxy only reads the ClientHello bytes required to find SNI, sends those bytes to the upstream server, and then pipes both TCP streams.

## Requirements

- Go `1.21`

## Build

```sh
go build -o sni-proxy .
```

## Run

Binding to ports `80` and `443` usually requires elevated privileges:

```sh
sudo ./sni-proxy
```

For local testing without privileged ports:

```sh
./sni-proxy -http-listen :8080 -https-listen :8443
```

## Configuration

By default, the proxy reads `config.yaml` from the current working directory. If the default file is missing, the proxy uses built-in defaults.

```yaml
log_level: info

client_whitelist:
  - 192.0.2.10
  - 198.51.100.0/24
  - "2001:db8::/64"

domain_whitelist:
  - example.com
  - ipv6.example.com

hosts:
  example.com: 203.0.113.10
  ipv6.example.com: "2001:db8::10"

ip_family:
  example.com: ipv4
  ipv6.example.com: ipv6

outbound_ip:
  example.com: 198.51.100.20
  pool.example.com: 198.51.100.20/24
  ipv6.example.com: "2001:db8::20"
  ipv6-pool.example.com: "2001:db8::20/64"
```

Supported `log_level` values are `debug`, `info`, `warn`, and `error`. Per-request routing logs are printed only when `log_level` is `debug`.

The optional `client_whitelist` list restricts which source IP addresses can connect to the proxy. Values can be single IP addresses or CIDR prefixes. When the list is empty or omitted, all clients are allowed. When it is configured, non-matching clients are rejected before HTTP or TLS routing is processed.

The optional `domain_whitelist` list restricts which domains can be proxied. Values are exact domain names. When the list is empty or omitted, all domains are allowed. When it is configured, HTTPS requests are allowed only if the SNI is listed; HTTP requests use the `Host` header for the same check.

The optional `hosts` map works like a small per-proxy hosts file. Keys are domain names, and values must be IP addresses. When a request host or SNI matches a configured domain, the proxy connects directly to that IP address and keeps the original port. For HTTPS, TLS is still passed through unchanged, so the client SNI remains the original domain.

The optional `ip_family` map forces matching domains to use IPv4 or IPv6. Supported values are `ipv4` and `ipv6`. When used without a `hosts` entry, the proxy dials with `tcp4` or `tcp6`, which constrains DNS resolution to that address family. When used with `hosts`, the configured IP address must match the forced family.

The optional `outbound_ip` map binds matching upstream connections to a specific local source IP address. Values can be a single IP address or a CIDR prefix. When a CIDR prefix is configured, the proxy picks a random source IP from that prefix for each upstream connection. For IPv4 prefixes larger than `/31`, network and broadcast addresses are skipped. This only affects outbound connections to upstream servers; the proxy still listens on all configured listen addresses. If `outbound_ip` is used with `ip_family` or `hosts`, all configured addresses for that domain must use the same IP family.

The selected outbound IP must be usable by the operating system. On Linux, that usually means the address is assigned to the host, or the system is configured to allow non-local source binding.

## Flags

- `-config`: YAML configuration file path, default `config.yaml`
- `-http-listen`: HTTP listen address, default `:80`
- `-https-listen`: HTTPS listen address, default `:443`
- `-dial-timeout`: upstream TCP dial timeout, default `10s`
- `-read-timeout`: initial client read timeout, default `10s`
