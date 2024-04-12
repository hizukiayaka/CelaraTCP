# CelaraTCP

CelaraTCP makes selected traffic look and behave like ordinary TCP egress
to soften ISP QoS / traffic classification side effects.
**It is not a VPN** and provides no encryption or authentication.

---

## Name — Why “CelaraTCP”
**Celara** nods to *celer* (Latin: “swift”), i.e., “get TCP-looking paths
to move smoothly.” **TCP** highlights that the system **mimics TCP shape** on
egress rather than building an L3/L4 tunnel.

---

## What It Is / What It Is Not
**It is**
- A local/edge toolchain for **re-packaging and forwarding** flows so that
  they are treated like regular TCP by middleboxes/ISPs.
- A practical of **TUN**, and optional **eBPF** to steer/shape traffic.

**It is not**
- **Not a VPN**. No confidentiality, integrity, or identity guarantees.
  Use TLS/QUIC/VPN on top if you need security.
- Not a promise to bypass policy. Intended for research/compatibility scenarios only.

---

## Platforms
- **Tier-1 (supported)**: **GNU/Linux**, **OpenWrt**
- **Planned**: **FreeBSD** (netmap/if_tun exploration), **Linux XDP**
   (TX/egress acceleration on capable NICs)

---

## License

This project is licensed under AGPL-3.0, with specific components
(eBPF) under GPL-2.0.
See [LICENSE.md](./LICENSE.md) for full licensing details.

## Contributing

By contributing, you agree to the [Contributor License Agreement](./CLA.md).
