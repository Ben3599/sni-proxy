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

## Flags

- `-http-listen`: HTTP listen address, default `:80`
- `-https-listen`: HTTPS listen address, default `:443`
- `-dial-timeout`: upstream TCP dial timeout, default `10s`
- `-read-timeout`: initial client read timeout, default `10s`
