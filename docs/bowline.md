---
layout: default
title: bowline
rank: 2
---

# `bowline`

`bowline` is a DNS full resolver (cache server) which supports:

* Basic feature of DNS full resolvers (RFC 1123)
* DNS over UDP 53 and TCP 53
* DNS over TLS (RFC7858), QUIC (RFC 9250), H2 and H3 (RFC 8484) for communication with stub resolvers
* DNSSEC for communication with authoritative servers (RFC 9364)
* Negative Trust Anchor
* stub-zone, local-zone, local-data
* DNSTAP for logging
* Web API (for reloading etc)
* Monitor console
* Prometheus

## Releases

* [Binaries are available](https://github.com/iijlab/dnsext/releases)

## Configuration

* [`bowline.conf`](https://github.com/iijlab/dnsext/blob/main/dnsext-bowline/bowline/bowline.conf)
* [`local-example.conf`](https://github.com/iijlab/dnsext/blob/main/dnsext-bowline/bowline/local-example.conf)
* [`stub-example.conf`](https://github.com/iijlab/dnsext/blob/main/dnsext-bowline/bowline/stub-example.conf)

## Executing

```
% sudo bowline bowline.conf
```

If `bowline` runs well, a monitor console is provided via stdin/stdout. Type `help` to know its commands.

## Web API

Send `GET` to the following path:

* `/metrics`: get stats
* `/stats`: get stats
* `/wstats`: get workers' stats
* `/reopen-log`: reopen a log file
* `/reload`: reload
* `/keep-cache`: Reloading with the cache kept
* `/quit`: quit
* `/help`: display help
* `/`: display help
