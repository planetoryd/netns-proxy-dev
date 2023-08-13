
- Package for Nix
- Handle DNS better. 
    - In-NS netfilter redirection. refer to /etc/resolvd
    - `/etc/resolv.conf` by default doesnt point to 127.0.0.53, but 192.168.x.x which will go nowhere.
- Check deps

`RUST_LIB_BACKTRACE=1` for backtrace
`RUST_LOG=trace`

### Debugging

```bash

sudo ./setsuid.sh $(which lldb-server)
lldb-server p --server --listen "*:2222"

# have to attach to child processes

# LLDB ext in vscode has bugs. so no.

gdbserver --no-startup-with-shell 10.27.0.1:2222 ./target/debug/test-sub

# it hangs with shell. no idea.

set follow-fork-mode child # parent

```

```
RUSTFLAGS='-C force-frame-pointers=yes -Zinstrument-mcount -Cpasses=ee-instrument<post-inline>'
```

## Networking

- An app connects to a host
    - DNS requests are handled by dnsproxy
    - IP packets are handled by Tun2socks, which directs traffic through a veth to an external socks5proxy
    - This provides compatibility but is not as efficient as the direct-socks5 way
    - Many apps either don't support socks5 proxy, or leak traffic/DNS.
- An app with sock5 proxy support
    - Two ways
        1. App connects to the socks proxy through a veth
        2. App connects to the IP endpoint in NS, and Netns-proxy forwards it to the provided socks proxy
- An app with HTTP proxy support
    - Works with I2P
        1. Veth
        2. Userspace proxy

- Ideal situation
    - The app connects to the socks5/http proxy endpoint in NS, and any leaked traffic is handled by tun2socks. Direct connection to socks proxy avoids the roundtrips of in-NS local DNS. The upstream socks5 proxy resolves hosts through proxy servers.

### DNS

By default, DNS requests (all traffic with port 53) are directed to the `dnsproxy` in NS. 

It may be problematic if an app uses its own DNS, as its traffic gets redirected elsewhere.

## Security

- How much security do I gain from this setup ?

I don't know how netfilter works, but netns seems relatively clear to me.
The tool puts applications into individual netns-es, connected with each other by veths.

Netns is foolproof. Netfilter can get messed up by other firewalls, mistakes. Interfaces go down and packets get sent through unexpected routes.

- proxychains uses LD_PRELOAD, which can fail for certain binaries.

## On decentralized protocols

They should stay away from conventional IP stack. They are out of scope for netns-proxy.

Yggdrasil should not expose an IP interface (TUN). It should just expose a unix socket.

## todo

- test ns setups
- test dns
- proxy chaining with go-gost
- explainer socks socks5h
- profile creation wizard
- live reload config
- check all sockets have root perms
    - root owned sockets can only be connected by root procs