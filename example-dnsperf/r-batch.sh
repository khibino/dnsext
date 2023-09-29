#!/bin/sh

set -x

port=1053
if [ x"$1" != x ]; then
    port="$1"
fi

sec=20
if [ x"$2" != x ]; then
    sec="$2"
fi

dig @127.0.0.1 a.root-servers.net. A -p $port
dig @127.0.0.1 b.root-servers.net. A -p $port
dig @127.0.0.1 c.root-servers.net. A -p $port
dig @127.0.0.1 d.root-servers.net. A -p $port

dnsperf -p $port -l $sec -d r4.txt
