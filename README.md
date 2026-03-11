# secure-chat-protocol

A decentralised, end-to-end encrypted overlay chat system built in Python. Implements a class-standardised secure communication protocol (SOCP v1.3) over a full-mesh WebSocket topology with RSA-4096 cryptography, server gossip, and SQLite-backed message persistence.

Built as part of an advanced secure programming unit at the University of Adelaide — the protocol spec was designed collaboratively by the entire cohort, with each group implementing it independently for interoperability testing and a peer-led code review / ethical hackathon.

---

## Features

| Feature | Status |
|---|---|
| End-to-end encrypted direct messages | ✅ Fully implemented |
| User presence (online list) | ✅ Fully implemented |
| Server mesh networking (n-to-n) | ✅ Fully implemented |
| Offline message queueing | ✅ Fully implemented |
| Replay attack prevention | ✅ Fully implemented |
| Public channel broadcast | ⚠️ Partial (encryption simplified) |
| File transfer | ❌ Not implemented |

---

## Security Design

- **RSA-4096** for all encryption and signatures (SOCP v1.3 mandated — no symmetric shortcuts)
- **RSA-OAEP (SHA-256)** for message payload encryption
- **RSASSA-PSS (SHA-256)** for both content signatures (end-to-end) and transport signatures (hop-by-hop)
- **Public key pinning** for introducer/bootstrap nodes
- **Message deduplication** to prevent replay attacks
- All server-to-server frames are signed; signature verification is enforced on receipt

---

## Architecture

```
Client ←→ Local Server ←→ Remote Servers ←→ Remote Clients
```

- Clients connect to exactly one local server via WebSocket
- Servers form a **full mesh** — all-to-all connections, no central broker
- Message routing is based on a `user_locations` table maintained via gossip
- There is no single point of failure; any node can go down without collapsing the network

Each server maintains a **SQLite database** with:
- Users (user ID, public key, home server, online status)
- Known servers (host, port, public key, connection state)
- Offline message queue (delivered on reconnect)
- Audit log

---

## Installation

**Requirements:** Python 3.11+

```bash
# Clone the repo
git clone https://github.com/yourusername/secure-chat-protocol.git
cd secure-chat-protocol

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .\.venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt
```

**Dependencies:** `websockets>=11.0`, `cryptography>=41.0`

---

## Running the System

### Step 1 — Start an introducer node

```bash
python node.py --uuid introducer_1 --host 0.0.0.0 --port 9001 --introducer
```

This prints the introducer's RSA public key. Copy it.

### Step 2 — Configure bootstrap.yaml

```yaml
bootstrap_servers:
  - host: "127.0.0.1"
    port: 9001
    pubkey: "<PASTE_PUBKEY_HERE>"
```

### Step 3 — Start additional server nodes (optional)

```bash
python node.py --uuid server_2 --host 0.0.0.0 --port 9002
```

Each node will automatically read `bootstrap.yaml`, join the network via the introducer, and connect to all known peers.

### Step 4 — Start clients

```bash
# In separate terminals
python client.py --host 127.0.0.1 --port 9001 --user Alice
python client.py --host 127.0.0.1 --port 9001 --user Bob
```

On first run you'll be prompted to set a password. On subsequent runs, the password is verified before access is granted.

---

## Client Commands

```
/list               List all currently online users
/tell <user> <msg>  Send an encrypted direct message
/all <msg>          Broadcast to the public channel
/quit  or  :q       Disconnect and exit
```

---

## Example Session

```
# Terminal 1 — Alice
> /list
[online] Alice, Bob

> /tell Bob Hey, this is end-to-end encrypted.

# Terminal 2 — Bob
[dm from Alice]: Hey, this is end-to-end encrypted.

> /tell Alice Nice. RSA-4096 for a chat app feels like overkill.
```

---

## Interoperability Testing

This system was designed to interoperate with other groups' independent implementations of the same SOCP v1.3 spec. To connect to an external node:

```bash
# Option A — add to bootstrap.yaml before starting
# Option B — connect directly at startup
python node.py --uuid myserver --peer <their_host>:<their_port>
```

Your server will automatically exchange server lists, sync user presence, and route messages across the combined mesh.

---

## Protocol Compliance (SOCP v1.3)

| Requirement | Status |
|---|---|
| RSA-4096 keys | ✅ |
| RSA-OAEP (SHA-256) encryption | ✅ |
| RSASSA-PSS (SHA-256) signatures | ✅ |
| Content signatures (end-to-end) | ✅ |
| Transport signatures (hop-by-hop) | ✅ |
| USER_ADVERTISE / USER_REMOVE gossip | ✅ |
| SERVER_DELIVER with loop suppression | ✅ |
| Heartbeats (15s interval, 45s timeout) | ✅ |
| Error codes (USER_NOT_FOUND, BAD_KEY, etc.) | ✅ |
| WebSocket transport (RFC 6455) | ✅ |

---

## Files

```
node.py              — Server node (mesh participant + introducer mode)
client.py            — Terminal client application
server_database.py   — SQLite persistence layer
bootstrap.yaml       — Introducer/bootstrap configuration
requirements.txt     — Python dependencies
```

---

## Authors

Group 69 — University of Adelaide, COMP SCI 3023

- Jack Feckner
- Pezhman Beheshtian
- Akshar Kalicharan Brahmbhatt
- Pranshu Bhaihetalbhai Mehta
