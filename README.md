
# DNSspoofer

A **DNS spoofing engine written in Go**, usable both as:

- a **standalone CLI tool**
- a **public Go library / API** for building custom DNS interception, poisoning, or testing tooling

The CLI in `cmd/dnsspoofer` is just a **thin wrapper** around the engine.

---

## Features

* Spoof DNS requests and responses for IPv4, IPv6, or both.
* Supports local and remote packet scopes.
* Wildcard hostname support via hosts file.
* Configurable NFQUEUE binding for packet interception.

---

## Installation

### Prerequisites

* Linux system with `nftables` support.
* Go 1.21+ installed.
* Root privileges for packet interception and nftables rules.
* `go-figure`, `gopacket`, `go-nfqueue`, and `urfave/cli` dependencies.

```bash
git clone https://github.com/Onyz107/dnsspoofer.git
cd dnsspoofer
go build -o dnsspoofer ./cmd/dnsspoofer
```

---

## Usage

### CLI
#### Give the program capabilities to modify NFTables
```bash
sudo setcap cap_net_admin=+ep ./dnsspoofer
```

#### Run
```bash
./dnsspoofer --interface eth0 --hosts /path/to/hosts.txt [--ip-mode ipv4|ipv6|ipv4+ipv6] [--spoof-mode aggressive|passive] [--scope local|remote] [--queue 0]
```

### Flags

| Flag           | Alias | Description                                                         | Default      |
| -------------- | ----- | ------------------------------------------------------------------- | ------------ |
| `--interface`  | `-i`  | Network interface to use                                            | **Required** |
| `--ip-mode`    | `-im` | IP stack to spoof (`ipv4`, `ipv6`, `ipv4+ipv6`)                     | `ipv4+ipv6`  |
| `--spoof-mode` | `-sm` | Spoofing behavior (`aggressive` or `passive`)                       | `passive`    |
| `--hosts`      |       | Path to hosts(5)-formatted file with hostname patterns              | **Required** |
| `--scope`      | `-s`  | Packet scope (`local` for OUTPUT chain, `remote` for FORWARD chain) | `remote`     |
| `--queue`      | `-q`  | NFQUEUE number to bind to                                           | `0`          |

---

### Hosts File Format

* Each line must contain a single IP and a single hostname pattern (wildcards allowed).
* Comments supported using `#`.
* Example:

```
192.168.1.100 example.com
10.0.0.50 *.ads.example.net # Block ads
```

If a hostname matches multiple patterns the last pattern will be used.

---

## Public Go API Usage

### Minimal Example

```go
iface, _ := net.InterfaceByName("eth0")

hosts := dnsspoofer.Hosts{
    "example.com.": []net.IP{net.ParseIP("10.0.0.123")},
}

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

engine := dnsspoofer.New(&dnsspoofer.EngineOptions{
    Iface:     iface,
    IPMode:    dnsspoofer.IPv4AndIPv6,
    SpoofMode: dnsspoofer.Passive,
    Scope:     dnsspoofer.Remote,
    Hosts:     hosts,
    Queue:     0,
})
defer engine.Stop() // Not mandatory but recommended in case the context is not cancelled

engine.Run(ctx)
```

---

## Engine API

### `EngineOptions`
```go
type IPMode uint32
type SpoofMode uint32
type Scope uint32
type Hosts map[*regexp.Regexp][]net.IP
```


```go
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

* `New(opts *EngineOptions) *Engine`
* `Run(ctx context.Context) error`
* `Stop()`

Context cancellation **fully tears down nftables rules and NFQUEUE**.

---

## Logger Interface

You can inject your own logger:

```go
type Logger interface {
	nfqueue.Logger
	Debug(msg any, args ...any)
	Error(msg any, args ...any)
	Info(msg any, args ...any)
}
```

If `Logger` is `nil`, a **dev/null logger** is used.

---

## Spoofing Modes

* **Aggressive:** Intercepts DNS requests and responds with spoofed IPs. Drops the original request.
* **Passive:** Intercepts DNS responses and modifies them with spoofed IPs.

---

## IP Modes

* `ipv4`: Spoof only DNS packets that are sent over IPv4.
* `ipv6`: Spoof only DNS packets that are sent over IPv6.
* `ipv4+ipv6`: Spoof both.

---

## Scope

* `local`: Spoof only packets from the local machine.
* `remote`: Spoof packets from other machines on the network (MITM scenarios).

---

## Packet Flow Overview

### Passive Mode (default) — *Modify DNS responses*

Used when you **don’t want to break normal resolution**, just alter the answers.

```
Client ──▶ DNS Query ──▶ Resolver ──▶ DNS Response ──▶ nftables
                                                            │
                                                            ▼
                                                         NFQUEUE
                                                            │
                                                            ▼
                                            ┌──────── match hostname? ────────┐
                                            │                                 │
                                        NO MATCH                           MATCH
                                            │                                 │
                                            ▼                                 ▼
                                    ACCEPT (unchanged)            Modify A / AAAA records
                                                                              │
                                                                              ▼
                                                                       ACCEPT (modified)
                                                                              │
                                                                              ▼
                                                                           Client
```

**Key points**

* Hooks on **INPUT** (local) or **FORWARD** (remote)
* Only touches packets **from port 53**
* Safest and stealthiest mode
* Best for MITM and transparent poisoning

---

### Aggressive Mode — *Answer DNS requests yourself*

Used when you want **full control** and don’t care about upstream DNS.

```
Client ──▶ DNS Query ──▶ nftables
                            │
                            ▼
                         NFQUEUE
                            │
                            ▼
                ┌──── match hostname? ────┐
                │                         │
            NO MATCH                    MATCH
                │                         │
                ▼                         ▼
     ACCEPT (forward upstream)    Forge DNS response
                                          │
                                          ▼
                                   Send spoofed reply
                                          │
                                          ▼
                                  DROP original request
```

**Key points**

* Hooks on **OUTPUT** (local) or **FORWARD** (remote)
* Intercepts **dport 53**
* Faster responses
* No upstream resolver involved
* More detectable, but very effective

---

## Local vs Remote Scope

### Local (`--scope local`)

```
Application ──▶ OUTPUT ──▶ NFQUEUE ──▶ Application
```

* Only affects the current machine
* Useful for testing or sandboxing

### Remote (`--scope remote`)

```
Client ──▶ FORWARD ──▶ NFQUEUE ──▶ Router ──▶ Internet
```

* Router / MITM position
* Affects all passing traffic
* Requires IP forwarding enabled

---

## Decision Matrix

| Goal             | Recommended Mode |
| ---------------- | ---------------- |
| Stealth          | Passive          |
| Speed            | Aggressive       |
| Replace resolver | Aggressive       |

If you’re doing MITM you probably should use passive mode, unless you know what you are doing.

---


## Caveats & Limitations

DNSspoofer is powerful, but there are **important limitations** to keep in mind:

1. **MITM required for remote traffic**

   * For IPv4: You must position yourself in the middle using **ARP spoofing** or equivalent techniques.
   * For IPv6: Use **NDP spoofing**.
   * Without MITM, remote clients’ DNS traffic will **never reach your NFQUEUE**, so spoofing won’t occur.

2. **Encrypted DNS breaks spoofing**

   * **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)** bypass the system resolver entirely.
   * These queries are encrypted and will **not hit the standard UDP port 53**, so your spoofing rules will not affect them.

3. **Wildcard matching**

   * Only supported in hosts files using `*` patterns (e.g., `*.ads.example.com`).
   * No support for regex or advanced DNS logic.
  
4. **TCP DNS is mostly ignored**

    * This tool only handles **UDP DNS**.
    * Large responses (DNSSEC, many records) may fall back to **TCP/53**.
    * Result: those queries will **bypass spoofing**.

    > Though ~95% of DNS is still UDP.

5. **DNSSEC is silently broken**

    * If a client **validates DNSSEC**, your spoofed answers will be rejected.
    * Passive mode makes this worse because you modify signed responses.

    Symptoms

    * Pages fail to load
    * “DNS_PROBE_FINISHED_BAD_SECURE_CONFIG”

    > This tool does not strip DNSSEC flags or forge signatures. That’s intentional, doing it right is complex and noisy.



6. **Encrypted DNS breaks spoofing (Again)**

    * Browsers and apps may use:

        * `8.8.8.8`
        * `1.1.1.1`
        * Built‑in DoH endpoints
    * Even with MITM, they might **pin certs** or retry encrypted DNS.

    > Aggressive mode helps here, but only if traffic actually hits port 53.


7. **IPv6 is often forgotten (and breaks expectations)**

    * Many modern networks now prefer **IPv6**.
    * If you don’t:
        * Enable IPv6 forwarding
        * Spoof NDP
        * Use `ipv4+ipv6`

    …clients will resolve via IPv6 and **completely ignore your spoofing**.


8. **System resolvers can cache aggressively**

    * OS resolvers may cache results longer than TTL.
    * Browsers may cache independently.


9. **This is not stealthy against monitoring**

    * IDS / IPS can detect:
        * Duplicate DNS IDs
        * Timing anomalies
        * Inconsistent TTLs

---

## "It doesn't work"
### If this tool “doesn’t work”, it’s almost always because:
* You are not in a MITM position
* The client is using DoH / DoT
* IPv6 is resolving instead of IPv4

---

## Working Around DoH / DoT

DNSspoofer cannot directly intercept **DNS‑over‑HTTPS (DoH)** or **DNS‑over‑TLS (DoT)**, since those protocols encrypt DNS traffic and avoid UDP port 53 entirely.

However, there is a **pragmatic but unreliable workaround** that may work in some environments.

### The Idea

Most browsers and systems hardcode a list of known DoH / DoT provider hostnames, such as:

* `dns.google`
* `cloudflare-dns.com`
* `mozilla.cloudflare-dns.com`
* `dns.quad9.net`

If these endpoints are **unreachable or fail repeatedly**, some clients will **fallback to classic DNS (UDP/53)**.

### DNS bootstrap attack

You can add known DoH/DoT provider hostnames to your hosts file and redirect them to:

* Your own machine
* A non-routable IP
* An IP that intentionally drops traffic

Example:

```
0.0.0.0 dns.google
0.0.0.0 cloudflare-dns.com
0.0.0.0 mozilla.cloudflare-dns.com
0.0.0.0 dns.quad9.net
```

Once the browser fails to reach its DoH endpoint multiple times, it *may* fallback to the system resolver, at which point DNSspoofer can intercept traffic normally.

---

### Important Warnings

This approach is **not reliable** and **not universal**:

* Some browsers **never fallback** (or only after restart)
* Some cache DoH failures aggressively
* Some apps pin IPs or certificates
* Future updates may remove fallback entirely

This is called a ***DNS bootstrap attack*** and it is **not a real DoH bypass**, just a **behavioral downgrade attack** that depends on client implementation details.s

> Treat this as a convenience trick, not a core feature.

---

## Security Disclaimer

This software is intended **for educational, research, and authorized security testing purposes only**.

DNSspoofer actively intercepts and modifies network traffic. Running it on networks, systems, or devices **without explicit authorization** may be illegal and unethical. The author and contributors **do not condone** unauthorized interception, manipulation, or disruption of network communications.

By using this tool, you acknowledge that:
* You are **legally permitted** to test the target network.
* You understand the **operational and legal risks** of DNS spoofing.
* You accept **full responsibility** for any damage, data loss, service disruption, or legal consequences resulting from its use.

This project is provided **“as is”**, without warranty of any kind.
Use responsibly. If you don’t have permission, **don’t be an asshole**.

---

## TODO
* Add DNSSEC support
* Handle DNS over TCP
* Handle DoH/DoT properly