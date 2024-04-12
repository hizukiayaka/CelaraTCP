# License for CelaraTCP

CelaraTCP – A high-performance networking framework with eBPF integration.

Copyright (c) [2024] [Hsia-Jun Li]

---

## 1. Default License – Entire Project Except eBPF Code

Unless explicitly stated otherwise, the **entire CelaraTCP project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)**.  
See: https://www.gnu.org/licenses/agpl-3.0.html

This applies to all parts of the project including, but not limited to:

- Application logic
- Networking components
- Command-line tools
- Utilities and supporting scripts
- Configuration files
- Documentation
- Any source code **not** intended to be executed within the Linux kernel

AGPL-3.0 is a strong copyleft license. If you modify and use the software over a network (e.g., as a service),
you are required to make the modified source code available under the same license.

---

## 2. Exception – eBPF Kernel Code

Certain components of this project are written specifically for in-kernel execution via the Linux eBPF subsystem.
These components (typically located under `ebpf/` or otherwise marked) are licensed under:

**GNU General Public License v2.0 (GPL-2.0)**  
See: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

These components are designed to comply with the Linux kernel’s licensing requirements.

### Syscall / UAPI Exception

To avoid unintended license propagation due to interactions with eBPF code, the following exception is granted:

> **User-space components that interact with the eBPF kernel code solely via standard syscall mechanisms,
ring buffers, or UAPI-defined interfaces are not considered derivative works** of the GPL-2.0 components.
Therefore, they are not subject to the GPL-2.0 license, even if they include or reference eBPF-related
headers provided by this project.

---

## 3. Third-Party Components

CelaraTCP includes third-party dependencies, each retaining its original license. These are used in ways compatible
with AGPL-3.0 and GPL-2.0.

| Component             | License                  |
|-----------------------|--------------------------|
| Standalone Asio       | Boost Software License 1.0 |
| libnl                 | LGPL v2.1               |
| Abseil                | Apache License 2.0      |
| spdlog                | MIT License             |
| Recycle Pool Utility  | BSD 2-Clause License    |

No modifications have been made to these libraries unless otherwise stated.

For LGPL-licensed components (e.g., libnl), we recommend dynamic linking and compliance with all
applicable license requirements.

---

## 4. Contributor License Agreement (CLA)

All contributors must agree to the Contributor License Agreement (CLA) before their contributions can be accepted.

By signing the CLA, contributors:

- Grant the project maintainers the right to use, sublicense, and relicense their contributions under any license,
  including **commercial closed-source licenses**
- Retain full ownership and authorship of their contributions
- Will receive appropriate attribution in all distributed versions

See [`CLA.md`](./CLA.md) for details.

---

## 5. Commercial Licensing

CelaraTCP is available for commercial licensing under closed-source terms.
For inquiries regarding commercial use, redistribution, or proprietary integration, please contact:

📩 Contact:
- 🌐 https://www.soulik.info
- 📧 cmFuZHlAc291bGlrLmluZm8K (base64 encoded)
