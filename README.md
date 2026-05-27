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

routes:
  example.com:
    host: 203.0.113.10
    ip_family: ipv4
    outbound_ip: 198.51.100.20
  pool.example.com:
    outbound_ip: 198.51.100.20/24
  ipv6.example.com:
    host: "2001:db8::10"
    ip_family: ipv6
    outbound_ip: "2001:db8::20/64"
```

Supported `log_level` values are `debug`, `info`, `warn`, and `error`. Per-request routing logs are printed only when `log_level` is `debug`.

The optional `client_whitelist` list restricts which source IP addresses can connect to the proxy. Values can be single IP addresses or CIDR prefixes. When the list is empty or omitted, all clients are allowed. When it is configured, non-matching clients are rejected before HTTP or TLS routing is processed.

The optional `domain_whitelist` list restricts which domains can be proxied. Values are exact domain names. When the list is empty or omitted, all domains are allowed. When it is configured, HTTPS requests are allowed only if the SNI is listed; HTTP requests use the `Host` header for the same check.

The optional `routes` map keeps per-domain upstream routing settings together. `host` works like a per-proxy hosts entry and must be an IP address. `ip_family` forces matching domains to use `ipv4` or `ipv6`. `outbound_ip` binds upstream connections to a local source IP address, and can be a single IP address or a CIDR prefix. When a CIDR prefix is configured, the proxy picks a random source IP from that prefix for each upstream connection. For IPv4 prefixes larger than `/31`, network and broadcast addresses are skipped. For HTTPS, TLS is still passed through unchanged, so the client SNI remains the original domain.

The older `hosts`, `ip_family`, and `outbound_ip` top-level maps are still accepted for compatibility. If the same domain appears in `routes`, the `routes` entry takes precedence over those legacy maps.

The selected outbound IP must be usable by the operating system. On Linux, that usually means the address is assigned to the host, or the system is configured to allow non-local source binding.

## Flags

- `-config`: YAML configuration file path, default `config.yaml`
- `-http-listen`: HTTP listen address, default `:80`
- `-https-listen`: HTTPS listen address, default `:443`
- `-dial-timeout`: upstream TCP dial timeout, default `10s`
- `-read-timeout`: initial client read timeout, default `10s`

## Recommendation

[1Password](https://1password.com/) is the best password manager I have used, and I recommend it.
