# DNSspoofer

**DNS spoofing engine written in Go**

Usable as:
- a **standalone CLI tool**
- a **Go library / API** for building DNS interception, poisoning, or testing tools

The CLI (`cmd/dnsspoofer`) is a thin wrapper around the engine.

---

## Features

- Spoof DNS for **IPv4**, **IPv6**, or both
- **Passive** (modify responses) and **Aggressive** (forge replies) modes
- Local or remote (MITM) packet interception
- Wildcard hostname support via hosts file
- nftables + NFQUEUE based interception

---

## Installation

### Requirements

- Linux with **nftables**
- Go **1.21+**
- Root or `cap_net_admin`

```bash
git clone https://github.com/Onyz107/dnsspoofer.git
cd dnsspoofer
go build -o dnsspoofer ./cmd/dnsspoofer
````

---

## Usage

### Capabilities

```bash
sudo setcap cap_net_admin=+ep ./dnsspoofer
```

### Run

```bash
./dnsspoofer --interface eth0 --hosts hosts.txt \
  [--ip-mode ipv4|ipv6|ipv4+ipv6] \
  [--spoof-mode aggressive|passive] \
  [--scope local|remote] \
  [--queue 0]
```

### Flags

| Flag           | Alias | Description                 | Default      |
| -------------- | ----- | --------------------------- | ------------ |
| `--interface`  | `-i`  | Network interface           | **Required** |
| `--hosts`      |       | hosts(5)-style file         | **Required** |
| `--ip-mode`    | `-im` | `ipv4`, `ipv6`, `ipv4+ipv6` | `ipv4+ipv6`  |
| `--spoof-mode` | `-sm` | `passive`, `aggressive`     | `passive`    |
| `--scope`      | `-s`  | `local` or `remote`         | `remote`     |
| `--queue`      | `-q`  | NFQUEUE number              | `0`          |

---

## Hosts File

* hosts(5) format
* `*` wildcards supported
* `#` for comments

### Example

```
192.168.2.101 example.com *.example.com
fe80::20c:29ff:fe31:d39b example.com *.example.com # IPv6 Address
```

### Result
```go
map["^example\.com$":["192.168.2.101", "fe80::20c:29ff:fe31:d39b"], "^.*\.example\.com$":["192.168.2.101", "fe80::20c:29ff:fe31:d39b"]]
```
---

## Go API

### Minimal Example

```go
iface, _ := net.InterfaceByName("eth0")

host := regexp.MustCompile(`^example\.com\.$`)
ip := net.ParseIP("10.0.0.123")

engine := dnsspoofer.New(&dnsspoofer.EngineOptions{
    Iface: iface,
    IPMode: dnsspoofer.IPv4AndIPv6,
    SpoofMode: dnsspoofer.Passive,
    Scope: dnsspoofer.Remote,
    Hosts: dnsspoofer.Hosts{
        host: []net.IP{ip},
    },
    Queue: 0,
})

ctx, cancel := context.WithCancel(context.Background())
defer cancel()
defer engine.Stop()

engine.Run(ctx)
```

### EngineOptions

```go
type Hosts map[*regexp.Regexp][]net.IP

type EngineOptions struct {
    Iface     *net.Interface
    IPMode    IPMode
    SpoofMode SpoofMode
    Scope     Scope
    Hosts     Hosts
    Queue     uint16
    Logger    Logger
}
```

### Lifecycle

* `New(opts)`
* `Run(ctx)`
* `Stop()`

Context cancellation **fully removes nftables rules and NFQUEUE**.

---

## Logger

Optional custom logger:

```go
type Logger interface {
    nfqueue.Logger
    Debug(msg any, args ...any)
    Info(msg any, args ...any)
    Error(msg any, args ...any)
}
```

If `nil`, logs are discarded.

---

## Spoofing Modes

### Passive (default)

* Modifies DNS **responses**
* Stealthy and safest
* Best for MITM

### Aggressive

* Intercepts DNS **queries**
* Sends forged replies
* Drops original request
* Faster, noisier, more detectable

---

## Scope

* **local**: only traffic from this machine (`OUTPUT`)
* **remote**: forwarded traffic (`FORWARD`, works with MITM)

---

## Caveats (Read This)

1. **Obviously MITM is required** for remote spoofing

   * For IPv4: ARP spoofing
   * For IPv6: NDP spoofing
   * Or both

2. **DoH / DoT bypasses this tool**

   * Encrypted DNS never hits UDP/53
   * Handling DoH / DoT  **would require a DNS server** not just a simple DNS spoofer, but even with a DNS server **the client will still get certificate warnings** because DoH / DoT is based on TLS

3. **UDP only**

   * TCP DNS is ignored
   * Large / DNSSEC responses may bypass spoofing
   > Though ~95% of DNS is over UDP

4. **DNSSEC will fail**

   * Signed responses get modified → validation breaks
   > Only if client validates DNSSEC, if it does not you're good

5. **Caching happens**

   * OS and browsers cache aggressively

6. **Not stealthy vs IDS**

   * Timing, TTL, and ID anomalies are detectable
   > This is intentional by design

---

## When “It Doesn’t Work”

It’s almost always because:

* You’re **not the MITM**
> Solution: depending on your attack type run **ARP and/or NDP spoofing**
* Traffic resolves over **IPv6**
> Solution: this is a common issue with skids that don't know what they're doing, solution is to **run a NDP spoofing attack**
* Client uses **DoH / DoT**
> Solution: see below

---

## DoH / DoT Downgrade (Hack)

You can *sometimes* force fallback by blocking known DoH endpoints to unreachable endpoints:

```
0.0.0.0 dns.google
0.0.0.0 cloudflare-dns.com
0.0.0.0 mozilla.cloudflare-dns.com
0.0.0.0 dns.quad9.net
```

This is unformally called a **DNS bootstrap attack**.

Not a real bypass. Use at your own risk.

---

## Security Disclaimer

For **authorized testing only**.

This tool intercepts and modifies network traffic. Using it without explicit permission is illegal. You are responsible for what you do with it.

If you don’t have permission, **don’t be an asshole**.

