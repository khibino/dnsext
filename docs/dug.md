---
layout: default
title: dug
rank: 3
---

# `dug`

`dug` is a stub resolver command like `dig`. There are two modes:

- Recursive query like `dig`
- Iterative query to visualize the algorithm used in `bowline`

Releases:

- [Binaries are available](https://github.com/iijlab/dnsext/releases)

Futher readings:

- [DNS検索コマンドdugの紹介](https://eng-blog.iij.ad.jp/archives/27527)

## Installation

`dug` command can be installed via homebrew.

```
brew install iijlab/tap/dug
```



## Recursive query

### Basic

Specify a target domain optionally plus record type. This pair can also be specified two times or more:

```
% dug www.iij.ad.jp a www.iijlab.net aaaa
;; 127.0.0.1#53/UDP, Tx:42bytes, Rx:58bytes
;; HEADER SECTION:
;Standard query, NoError, id: 36227
;Flags: Recursion Desired, Recursion Available


;; OPTIONAL PSEUDO EDNS SECTION:
;Version: 0, UDP: 1232, DNSSEC OK: False, Data:[]

;; QUESTION SECTION:
;www.iij.ad.jp.		IN	A

;; ANSWER SECTION:
www.iij.ad.jp.	221(3 mins)	IN	A	202.232.2.180

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; 127.0.0.1#53/UDP, Tx:43bytes, Rx:95bytes
;; HEADER SECTION:
;Standard query, NoError, id: 26739
;Flags: Recursion Desired, Recursion Available


;; OPTIONAL PSEUDO EDNS SECTION:
;Version: 0, UDP: 1232, DNSSEC OK: False, Data:[EDNSError{ info-code=18 extra-text="" [\# 0 ] }]

;; QUESTION SECTION:
;www.iijlab.net.		IN	AAAA

;; ANSWER SECTION:
www.iijlab.net.	3600(1 hour)	IN	CNAME	sh3.iijlab.net.
sh3.iijlab.net.	3600(1 hour)	IN	AAAA	2001:240:bb82:2706::1:49

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; 251usec

```

### DNS over TLS, QUIC, H2 and H3

Specify `dot`, `doq`, `h2` or `h3` to `-d`:

```
% dug 8.8.8.8 -d h2 www.iij.ad.jp a
;; 127.0.0.1#53/UDP, Tx:49bytes, Rx:73bytes
;; HEADER SECTION:
;Standard query, NoError, id: 35989
;Flags: Recursion Desired, Recursion Available


;; OPTIONAL PSEUDO EDNS SECTION:
;Version: 0, UDP: 1232, DNSSEC OK: False, Data:[]

;; QUESTION SECTION:
;8.8.8.8.in-addr.arpa.		IN	PTR

;; ANSWER SECTION:
8.8.8.8.in-addr.arpa.	80801(22 hours)	IN	PTR	dns.google.

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; 127.0.0.1#53/UDP, Tx:42bytes, Rx:58bytes
;; HEADER SECTION:
;Standard query, NoError, id: 40319
;Flags: Recursion Desired, Recursion Available


;; OPTIONAL PSEUDO EDNS SECTION:
;Version: 0, UDP: 1232, DNSSEC OK: False, Data:[]

;; QUESTION SECTION:
;www.iij.ad.jp.		IN	A

;; ANSWER SECTION:
www.iij.ad.jp.	198(3 mins)	IN	A	202.232.2.180

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; 80usec
```

### DDR (Discovery of Designated Resolvers)

Specify `auto` to `-d`:

```
% dug @1.1.1.1 -d auto -v www.iijlab.net aaaa
    query "_dns.resolver.arpa." SVCB to 1.1.1.1#53/UDP
RD_SVCB {
    svcb_priority = 1
  , svcb_target = "one.one.one.one."
  , svcb_params = {
        alpn=["h2","h3"]
      , port=443
      , ipv4hint=[1.1.1.1,1.0.0.1]
      , ipv6hint=[2606:4700:4700::1111,2606:4700:4700::1001]
      , dohpath="/dns-query{?dns}"}}
RD_SVCB {
    svcb_priority = 2
  , svcb_target = "one.one.one.one."
  , svcb_params = {
        alpn=["dot"]
      , port=853
      , ipv4hint=[1.1.1.1,1.0.0.1]
      , ipv6hint=[2606:4700:4700::1111,2606:4700:4700::1001]}}
;; 2606:4700:4700::1001#443/H2, Tx:43bytes, Rx:95bytes
;; HEADER SECTION:
;Standard query, NoError, id: 22308
;Flags: Recursion Desired, Recursion Available


;; OPTIONAL PSEUDO EDNS SECTION:
;Version: 0, UDP: 1232, DNSSEC OK: False, Data:[EDNSError{ info-code=18 extra-text="" [\# 0 ] }]

;; QUESTION SECTION:
;www.iijlab.net.		IN	AAAA

;; ANSWER SECTION:
www.iijlab.net.	3596(59 mins)	IN	CNAME	sh3.iijlab.net.
sh3.iijlab.net.	3596(59 mins)	IN	AAAA	2001:240:bb82:2706::1:49

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; 274usec
1.0.0.1#443/H2: v1.3(FullHandshake)
1.1.1.1#443/H2: v1.3(FullHandshake)
2606:4700:4700::1001#443/H2: v1.3(FullHandshake)
2606:4700:4700::1111#443/H2: v1.3(FullHandshake)
```

## Iterative query

Specify `-i`:

```
% dug www.iij.ad.jp -vv -i
resolve: query: "www.iij.ad.jp." A IN
    DnssecOK:0, CheckDisabled:0, AuthenticatedData:0
require-dnskey: query "." DNSKEY
    query "." DNSKEY to 199.7.83.42#53/UDP
    query "." DNSKEY to 2001:7fe::53#53/UDP
    query "." DNSKEY to 2001:7fe::53#53/TCP
    query "." DNSKEY to 2001:7fe::53#53/TCP: win
require-dnskey: verification success - RRGIG of DNSKEY: "."
root-priming: query "." NS
    query "." NS to 2001:500:1::53#53/UDP
    query "." NS to 2001:503:ba3e::2:30#53/UDP
    query "." NS to 2001:500:1::53#53/UDP: win
root-priming: verification success - RRSIG of NS: "."
    "a.root-servers.net." 198.41.0.4#53 2001:503:ba3e::2:30#53
    "b.root-servers.net." 170.247.170.2#53 2801:1b8:10::b#53
    "c.root-servers.net." 192.33.4.12#53 2001:500:2::c#53
    "d.root-servers.net." 199.7.91.13#53 2001:500:2d::d#53
    "e.root-servers.net." 192.203.230.10#53 2001:500:a8::e#53
    "f.root-servers.net." 192.5.5.241#53 2001:500:2f::f#53
    "g.root-servers.net." 192.112.36.4#53 2001:500:12::d0d#53
    "h.root-servers.net." 198.97.190.53#53 2001:500:1::53#53
    "i.root-servers.net." 192.36.148.17#53 2001:7fe::53#53
    "j.root-servers.net." 192.58.128.30#53 2001:503:c27::2:30#53
    "k.root-servers.net." 193.0.14.129#53 2001:7fd::1#53
    "l.root-servers.net." 199.7.83.42#53 2001:500:9f::42#53
    "m.root-servers.net." 202.12.27.33#53 2001:dc3::35#53
iterative: query "jp." A
    query "jp." A to 192.203.230.10#53/UDP
    query "jp." A to 192.5.5.241#53/UDP
    query "jp." A to 192.203.230.10#53/UDP: win
delegation - verification success - RRGIG of DS: "." -> "jp."
zone: "jp.":
    "a.dns.jp." 203.119.1.1#53 2001:dc4::1#53
    "b.dns.jp." 202.12.30.131#53 2001:dc2::1#53
    "c.dns.jp." 156.154.100.5#53 2001:502:ad09::5#53
    "d.dns.jp." 210.138.175.244#53 2001:240::53#53
    "e.dns.jp." 192.50.43.53#53 2001:200:c000::35#53
    "f.dns.jp." 150.100.6.8#53 2001:2f8:0:100::153#53
    "g.dns.jp." 203.119.40.1#53
    "h.dns.jp." 161.232.72.25#53 2a01:8840:1bc::25#53
require-dnskey: query "jp." DNSKEY
    query "jp." DNSKEY to 2001:dc2::1#53/UDP
    query "jp." DNSKEY to 156.154.100.5#53/UDP
    query "jp." DNSKEY to 2001:dc2::1#53/UDP: win
require-dnskey: verification success - RRGIG of DNSKEY: "jp."
iterative: query "ad.jp." A
    query "ad.jp." A to 203.119.40.1#53/UDP
    query "ad.jp." A to 150.100.6.8#53/UDP
    query "ad.jp." A to 203.119.40.1#53/UDP: win
delegation - no delegation: "jp." -> "ad.jp."
cache-soa: verification success - RRGIG of SOA: "jp."
iterative: query "iij.ad.jp." A
    query "iij.ad.jp." A to 156.154.100.5#53/UDP
    query "iij.ad.jp." A to 2001:200:c000::35#53/UDP
    query "iij.ad.jp." A to 2001:200:c000::35#53/UDP: win
delegation - verification success - RRGIG of DS: "jp." -> "iij.ad.jp."
zone: "iij.ad.jp.":
    "dns0.iij.ad.jp." 210.130.0.5#53 2001:240::105#53
    "dns1.iij.ad.jp." 210.130.1.5#53 2001:240::115#53
require-dnskey: query "iij.ad.jp." DNSKEY
    query "iij.ad.jp." DNSKEY to 2001:240::115#53/UDP
    query "iij.ad.jp." DNSKEY to 210.130.0.5#53/UDP
    query "iij.ad.jp." DNSKEY to 210.130.0.5#53/UDP: win
require-dnskey: verification success - RRGIG of DNSKEY: "iij.ad.jp."
iterative: query "www.iij.ad.jp." A
    query "www.iij.ad.jp." A to 2001:240::115#53/UDP
    query "www.iij.ad.jp." A to 210.130.0.5#53/UDP
    query "www.iij.ad.jp." A to 210.130.0.5#53/UDP: win
delegation - no delegation: "iij.ad.jp." -> "www.iij.ad.jp."
resolve-exact: skip exact query "www.iij.ad.jp." A for last no-delegation
verification success - RRGIG of A: "www.iij.ad.jp."
;; HEADER SECTION:
;Standard query, NoError, id: 0
;Flags: Recursion Available, Authentic Data


;; QUESTION SECTION:
;www.iij.ad.jp.		IN	A

;; ANSWER SECTION:
www.iij.ad.jp.	300(5 mins)	IN	A	202.232.2.180

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; 269usec
```
