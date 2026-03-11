"""
SOCP Node Server - Complete Version
Python 3.11+
Implements SOCP v1.3 Protocol
"""

import asyncio
import base64
import json
import time
import secrets
import argparse
import uuid
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Any, List

import websockets
from websockets.legacy.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Import database module
try:
    from server_database import ServerDatabase
except ImportError:
    ServerDatabase = None
    print("[warning] server_database.py not found, running without persistence")

# ---------------- base64url (no padding) ----------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

# ---------------- RSA helpers ----------------------

@dataclass
class RSAKeys:
    priv: rsa.RSAPrivateKey

    @staticmethod
    def generate(bits: int = 4096) -> "RSAKeys":
        return RSAKeys(rsa.generate_private_key(public_exponent=65537, key_size=bits))

    @property
    def pub_der(self) -> bytes:
        return self.priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

def rsa_pss_sign(priv: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )

def rsa_pss_verify(pub, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        return True
    except Exception:
        return False

def rsa_pub_from_b64u(b: str):
    return serialization.load_der_public_key(b64u_dec(b))

# ---------------- Envelope signing --------------------

def canon(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def transport_sig_preimage(payload: dict) -> bytes:
    return hashlib.sha256(canon(payload)).digest()

def dm_content_preimage(ciphertext_b64: str, from_id: str, to_id: str, ts: int) -> bytes:
    h = hashlib.sha256()
    try:
        ct_bytes = b64u_dec(ciphertext_b64 or "")
    except Exception:
        ct_bytes = (ciphertext_b64 or "").encode()
    h.update(ct_bytes)
    h.update(from_id.encode())
    h.update(to_id.encode())
    h.update(str(ts).encode())
    return h.digest()

def public_content_preimage(ciphertext_b64: str, from_id: str, ts: int) -> bytes:
    h = hashlib.sha256()
    try:
        ct_bytes = b64u_dec(ciphertext_b64 or "")
    except Exception:
        ct_bytes = (ciphertext_b64 or "").encode()
    h.update(ct_bytes)
    h.update(from_id.encode())
    h.update(str(ts).encode())
    return h.digest()

def keyshare_preimage(shares: list, creator_pub_b64: str) -> bytes:
    h = hashlib.sha256()
    h.update(canon(shares))
    h.update(creator_pub_b64.encode())
    return h.digest()

# ---------------- Link + Node -------------------------

@dataclass
class Link:
    ws: WebSocketServerProtocol
    peer_id: str

class Node:
    def __init__(self, server_uuid: str, host: str, port: int, introducer: bool = False, use_db: bool = True):
        self.server_uuid = server_uuid
        self.host = host
        self.port = port
        self.keys = RSAKeys.generate(4096)
        
        # Database persistence
        self.db = None
        if use_db and ServerDatabase:
            try:
                self.db = ServerDatabase(f"{server_uuid}_server.db")
                print(f"[db] Initialized database: {server_uuid}_server.db")
            except Exception as e:
                print(f"[db] Failed to initialize: {e}")
        
        # In-memory tables
        self.servers: Dict[str, Link] = {}
        self.server_addrs: Dict[str, Tuple[str, int]] = {}
        self.server_pubkeys: Dict[str, Any] = {}
        self.server_last_seen: Dict[str, float] = {}
        self.local_users: Dict[str, Link] = {}
        self.user_pubkeys: Dict[str, Any] = {}
        self.user_locations: Dict[str, str] = {}
        
        # Replay cache
        self.seen: Dict[str, float] = {}
        self.seen_ttl = 120.0
        self._stop = asyncio.Event()
        self.is_introducer = introducer
        self.hb_interval = 15.0
        self.hb_timeout = 45.0
        self.public_version = 1
        # List of usernames currently being registered - TOCTOU guard
        self._registering: set[str] = set()
        
        # Load from database
        if self.db:
            self._load_from_database()
        if self.db:
            self.db._audit_log_direct("NODE_START", self.server_uuid, f"Node started: {host}:{port} (introducer={introducer})", "INFO")
            
    def _load_from_database(self):
        if not self.db:
            return
        self.server_addrs = self.db.get_server_addrs_dict()
        for sid, pk_b64 in self.db.get_server_pubkeys_list():
            try:
                self.server_pubkeys[sid] = rsa_pub_from_b64u(pk_b64)
            except Exception:
                pass
        self.user_locations = self.db.get_user_locations_dict()
        pubkeys_dict = self.db.get_user_pubkeys_dict()
        for uid, pk_b64 in pubkeys_dict.items():
            try:
                self.user_pubkeys[uid] = rsa_pub_from_b64u(pk_b64)
            except Exception:
                pass
        stats = self.db.get_stats()
        print(f"[db] Loaded: {stats['total_users']} users ({stats['online_users']} online), {stats['total_servers']} servers, {stats['queued_messages']} queued")

    async def start(self):
        async with websockets.serve(self._handler, self.host, self.port, ping_interval=15, ping_timeout=30):
            print(f"[node] {self.server_uuid} listening ws://{self.host}:{self.port}")
            await self._stop.wait()

    def stop(self):
        self._stop.set()

    async def _handler(self, ws: WebSocketServerProtocol):
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            msg = json.loads(raw)
        except Exception:
            await ws.close(code=1000)
            return
        
        t = msg.get("type")
        if t == "PEER_HELLO_LINK":
            await self._on_peer_hello(ws, msg)
        elif t == "USER_HELLO":
            await self._on_user_hello(ws, msg)
        elif t == "SERVER_HELLO_JOIN" and self.is_introducer:
            await self._on_server_hello_join(ws, msg)
        elif t == "CTRL_USER_STATUS":
            try:
                await ws.close(code=1000)
            except Exception:
                pass
        elif t == "CTRL_GET_PRIVSTORE":
            await self._on_ctrl_get_privstore(ws, msg)
        elif t == "SERVER_ANNOUNCE":
            await self._on_server_announce(msg)
        elif t in ("SERVER_FILE_START", "SERVER_FILE_CHUNK", "SERVER_FILE_END"):
            await self._handle_server_file(msg)
        elif t in ("FILE_START", "FILE_CHUNK", "FILE_END"):
            await self._handle_peer_file_public(msg)
        else:
            await ws.close(code=1000)

    def env(self, typ: str, to_id: str, payload: dict, sign=True, from_id: Optional[str]=None) -> dict:
        env = {
            "type": typ,
            "from": from_id or self.server_uuid,
            "to": to_id,
            "ts": int(time.time() * 1000),
            "payload": payload,
            "sig": "",
        }
        if sign:
            pre = transport_sig_preimage(payload)
            env["sig"] = b64u(rsa_pss_sign(self.keys.priv, pre))
        return env

    async def _on_peer_hello(self, ws: WebSocketServerProtocol, msg: dict):
        suuid = msg.get("from")
        pl = msg.get("payload", {})
        # verify signature with the pubkey provided in payload
        try:
            pk_b64 = pl.get("pubkey", "")
            if not isinstance(pk_b64, str) or not pk_b64:
                await ws.close(code=1000)
                return
            peer_pub = rsa_pub_from_b64u(pk_b64)
            pre = transport_sig_preimage(pl)
            if not rsa_pss_verify(peer_pub, b64u_dec(msg.get("sig", "")), pre):
                await ws.close(code=1000)
                return
        except Exception:
            await ws.close(code=1000)
            return
        self.servers[suuid] = Link(ws, suuid)
        self.server_last_seen[suuid] = time.time()
        
        hp = (pl.get("host"), int(pl.get("port", 0)))
        if hp[0] and hp[1]:
            self.server_addrs[suuid] = hp
            if self.db:
                try:
                    pk_b64 = pl.get("pubkey", "")
                    self.db.add_or_update_server(suuid, hp[0], hp[1], pk_b64, is_connected=True)
                except Exception as e:
                    print(f"[db] Error persisting server: {e}")
        
        # Key record of verified peers public key
        try:
            self.server_pubkeys[suuid] = peer_pub
        except Exception:
            pass
        
        print(f"[peer] linked {suuid} @ {hp}")
        
        # Advertise local users
        try:
            for uid in list(self.local_users.keys()):
                pk_b64u = ""
                try:
                    pub = self.user_pubkeys.get(uid)
                    if pub is not None:
                        der = pub.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                        pk_b64u = b64u(der)
                except Exception:
                    pk_b64u = ""
                adv_meta = {"pubkey": pk_b64u}
                if self.db:
                    try:
                        row = self.db.get_user_by_name(uid)
                        if row and row.get("user_id"):
                            adv_meta["uuid"] = row.get("user_id")
                    except Exception:
                        pass
                adv = self.env("USER_ADVERTISE", suuid, 
                              {"user_id": uid, "server_id": self.server_uuid, "meta": adv_meta})
                await self._send(self.servers[suuid], adv)
        except Exception:
            pass
        
        await self._peer_loop(self.servers[suuid])

    async def _peer_loop(self, link: Link):
        try:
            async for raw in link.ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                await self._on_peer_msg(link, msg)
        except (ConnectionClosedOK, ConnectionClosedError):
            pass
        finally:
            if self.db:
                self.db.update_server_connection_status(link.peer_id, False)
            self.servers.pop(link.peer_id, None)
            self.server_last_seen.pop(link.peer_id, None)

    async def _on_peer_msg(self, link: Link, msg: dict):
        if not self._dedup(msg):
            return

        suuid = msg.get("from")
        self.server_last_seen[suuid] = time.time()
        
        if suuid and link.peer_id != suuid:
            if link.peer_id in self.servers and self.servers.get(link.peer_id) is link:
                self.servers.pop(link.peer_id, None)
            link.peer_id = suuid
            self.servers[suuid] = link
            print(f"[peer] remapped link to {suuid}")
        
        t = msg.get("type")

        if t not in ("PEER_HELLO_LINK", "SERVER_ANNOUNCE"):
            try:
                pub = self.server_pubkeys.get(suuid)
                if not pub:
                    return
                if not rsa_pss_verify(pub, b64u_dec(msg.get("sig", "")), transport_sig_preimage(msg.get("payload", {}))):
                    return
            except Exception:
                return
        
        if t == "PEER_DELIVER":
            await self._handle_peer_deliver(msg)
        elif t == "SERVER_DELIVER":
            await self._handle_server_deliver(msg)
        elif t == "HEARTBEAT":
            pass
        elif t == "MSG_PUBLIC_CHANNEL":
            await self._handle_msg_public_server(msg)
        elif t == "PUBLIC_CHANNEL_ADD":
            await self._handle_public_add(msg)
        elif t == "PUBLIC_CHANNEL_UPDATED":
            await self._handle_public_updated(msg)
        elif t == "PUBLIC_CHANNEL_KEY_SHARE":
            await self._handle_public_key_share(msg)
        elif t in ("SERVER_FILE_START", "SERVER_FILE_CHUNK", "SERVER_FILE_END"):
            await self._handle_server_file(msg)
        elif t in ("FILE_START", "FILE_CHUNK", "FILE_END"):
            await self._handle_peer_file_public(msg)
        elif t in ("USER_ADVERTISE", "USER_REMOVE"):
            await self._presence_update(msg)
            await self._broadcast(msg)
        elif t == "SERVER_ANNOUNCE":
            await self._on_server_announce(msg)

    async def _on_server_hello_join(self, ws: WebSocketServerProtocol, msg: dict):
        pl = msg.get("payload", {})
        pk_b64 = pl.get("pubkey", "")
        
        try:
            pub = rsa_pub_from_b64u(pk_b64)
            if not rsa_pss_verify(pub, b64u_dec(msg.get("sig", "")), transport_sig_preimage(pl)):
                await ws.close(code=1000)
                return
        except Exception:
            await ws.close(code=1000)
            return
        
        requested_id = msg.get("from") or ""
        assigned_id = requested_id if requested_id and requested_id not in self.server_addrs else f"server_{secrets.token_hex(4)}"
        
        servers_list: List[dict] = []
        for sid, (h, p) in list(self.server_addrs.items()):
            try:
                pk = self.server_pubkeys.get(sid)
                pk_s = b64u(pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)) if pk else ""
            except Exception:
                pk_s = ""
            servers_list.append({"server_id": sid, "host": h, "port": int(p), "pubkey": pk_s})
        
        try:
            pk_self = b64u(self.keys.pub_der)
        except Exception:
            pk_self = ""
        
        servers_list.append({"server_id": self.server_uuid, "host": self.host, "port": int(self.port), "pubkey": pk_self})
        
        welcome = self.env("SERVER_WELCOME", assigned_id, {"assigned_id": assigned_id, "servers": servers_list})
        try:
            print(welcome)
            await ws.send(json.dumps(welcome))
        except Exception:
            pass
        
        # NEW: Broadcast SERVER_ANNOUNCE to inform network of new server
        try:
            ann = self.env("SERVER_ANNOUNCE", "*", {
                "server_id": assigned_id,
                "host": pl.get("host", ""),
                "port": pl.get("port", 0),
                "pubkey": pk_b64
            })
            await self._broadcast(ann)
            print(f"[introducer] ✓ Broadcasted SERVER_ANNOUNCE for new server {assigned_id}")
            if self.db:
                self.db._audit_log_direct("SERVER_ANNOUNCE", assigned_id, 
                    "Announced new server join to network", "INFO")
        except Exception as e:
            print(f"[introducer] ERROR: Failed to broadcast SERVER_ANNOUNCE: {e}")
            if self.db:
                self.db._audit_log_direct("SERVER_ANNOUNCE_FAIL", assigned_id, 
                    f"Broadcast failed: {e}", "ERROR")
        
        await ws.close(code=1000)
        
    async def _on_user_hello(self, ws: WebSocketServerProtocol, msg: dict):
        uid = msg.get("from")
        pl = msg.get("payload", {})
        
        # Check name is not currently being registered. TOCTOU
        if isinstance(uid, str):
            if uid in self._registering:
                err = self.env("ERROR", uid, {"code": "NAME_IN_USE", "detail": uid})
                try:
                    await ws.send(json.dumps(err))
                except Exception:
                    pass
                try:
                    await ws.close(code=1000)
                except Exception:
                    pass
                return
            self._registering.add(uid)
        
        try:
            if uid in self.local_users or (uid in self.user_locations and self.user_locations.get(uid)):
                err = self.env("ERROR", uid, {"code":"NAME_IN_USE","detail":uid})
                print(err)
                await ws.send(json.dumps(err))
                await ws.close(code=1000)
                return
            
            if self.db:
                try:
                    known_loc = self.db.get_user_location(uid)
                    if known_loc and known_loc != self.server_uuid:
                        err = self.env("ERROR", uid, {"code":"NAME_IN_USE","detail":uid})
                        print(err)
                        await ws.send(json.dumps(err))
                        await ws.close(code=1000)
                        return
                except Exception:
                    pass
            
            try:
                pub = rsa_pub_from_b64u(pl.get("pubkey", ""))
                key_size = getattr(pub, "key_size", 0)
                if key_size < 4096:
                    err = self.env("ERROR", uid, {"code": "BAD_KEY", "detail": "too_small"})
                    print(err)
                    await ws.send(json.dumps(err))
                    await ws.close(code=1000)
                    return
                try:
                    e = pub.public_numbers().e
                    if e != 65537:
                        err = self.env("ERROR", uid, {"code": "BAD_KEY", "detail": "bad_exponent"})
                        print(err)
                        await ws.send(json.dumps(err))
                        await ws.close(code=1000)
                        return
                except Exception:
                    err = self.env("ERROR", uid, {"code": "BAD_KEY", "detail": "invalid_numbers"})
                    print(err)
                    await ws.send(json.dumps(err))
                    await ws.close(code=1000)
                    return
            except Exception:
                err = self.env("ERROR", uid, {"code":"BAD_KEY","detail":"invalid"})
                print(err)
                await ws.send(json.dumps(err))
                await ws.close(code=1000)
                return
            
            # verifier check.
            if self.db:
                try:
                    existing = self.db.get_user_by_name(uid)
                except Exception:
                    existing = None
                if existing and (existing.get("pake_password") or ""):
                    presented = pl.get("pake_password") or ""
                    if not presented:
                        err = self.env("ERROR", uid, {"code":"PASSWORD_REQUIRED","detail":uid})
                        await ws.send(json.dumps(err))
                        await ws.close(code=1000)
                        return
                    if presented != (existing.get("pake_password") or ""):
                        err = self.env("ERROR", uid, {"code":"BAD_PASSWORD","detail":uid})
                        await ws.send(json.dumps(err))
                        await ws.close(code=1000)
                        return

            # nonce signing
            challenge = secrets.token_bytes(32)
            ch_msg = self.env("AUTH_CHALLENGE", uid, {"challenge": b64u(challenge)})
            try:
                try:
                    print(f"[auth] sending AUTH_CHALLENGE to {uid}")
                except Exception:
                    pass
                await ws.send(json.dumps(ch_msg))
            except Exception:
                await ws.close(code=1000)
                return
            try:
                raw2 = await asyncio.wait_for(ws.recv(), timeout=8)
                proof = json.loads(raw2)
            except Exception:
                await ws.close(code=1000)
                return
            # log received AUTH_PROOF
            try:
                print({"log": "AUTH_PROOF", "from": uid, "payload": proof.get("payload", {})})
            except Exception:
                pass
        except Exception:
            await ws.close(code=1000)
            return
        if proof.get("type") != "AUTH_PROOF":
            await ws.close(code=1000)
            return
        ppl = proof.get("payload", {})
        ch_back = ppl.get("challenge") or ""
        sig_b64 = ppl.get("signature") or ""
        try:
            if b64u_dec(ch_back) != challenge:
                try:
                    print(f"[auth] challenge mismatch for {uid}")
                except Exception:
                    pass
                await ws.close(code=1000)
                return
            if not rsa_pss_verify(pub, b64u_dec(sig_b64), challenge):
                try:
                    print(f"[auth] signature verification failed for {uid}")
                except Exception:
                    pass
                await ws.close(code=1000)
                return
        except Exception:
            await ws.close(code=1000)
            return
        try:
            print(f"[auth] verified {uid}")
        except Exception:
            pass
        
        self.local_users[uid] = Link(ws, uid)
        self.user_pubkeys[uid] = pub
        self.user_locations[uid] = self.server_uuid
        
        if self.db:
            try:
                # Enforce unique usernames
                persist_id = pl.get("uuid") or ""
                try:
                    existing = self.db.get_user_by_name(uid)
                except Exception:
                    existing = None
                if existing and existing.get("user_id"):
                    persist_id = existing.get("user_id")
                if not persist_id:
                    persist_id = uid
                meta = {"name": uid, "uuid": persist_id}
                pstore = pl.get("privkey_store") or ""
                pake = pl.get("pake_password") or ""
                self.db.add_or_update_user(persist_id, pl.get("pubkey", ""), self.server_uuid, meta, pstore, pake)
            except Exception as e:
                print(f"[db] Error persisting user: {e}")
        
        print(f"[user] {uid} connected")
        
        # Deliver queued messages
        if self.db:
            try:
                queued = self.db.get_queued_messages(uid)
                if queued:
                    print(f"[db] Delivering {len(queued)} queued messages to {uid}")
                    msg_ids = []
                    for qmsg in queued:
                        env = self.env("USER_DELIVER", uid, {
                            "ciphertext": qmsg["ciphertext"],
                            "sender": qmsg["sender_id"],
                            "sender_pub": qmsg.get("sender_pub"),
                            "content_sig": qmsg.get("content_sig"),
                        })
                        await self._send(self.local_users[uid], env)
                        msg_ids.append(qmsg["id"])
                    self.db.mark_messages_delivered(msg_ids)
            except Exception as e:
                print(f"[db] Error delivering queued messages: {e}")
        
        # Advertise user
        adv_uuid = meta.get("uuid") if self.db else (pl.get("uuid", ""))
        adv = self.env("USER_ADVERTISE", "*", 
                      {"user_id": uid, "server_id": self.server_uuid, "meta": {"pubkey": pl.get("pubkey", ""), "uuid": adv_uuid}})
        await self._broadcast(adv)
        add_msg = self.env("PUBLIC_CHANNEL_ADD", "*", {"add": [uid], "if_version": 1})
        await self._broadcast(add_msg)
        self.public_version += 1
        upd_msg = self.env("PUBLIC_CHANNEL_UPDATED", "*", {"version": self.public_version, "wraps": []})
        await self._broadcast(upd_msg)

        await self._user_loop(self.local_users[uid])
        
        # Cleanup on disconnect
        self.local_users.pop(uid, None)
        if self.user_locations.get(uid) == self.server_uuid:
            self.user_locations.pop(uid, None)
        
        if self.db:
            try:
                self.db.update_user_status(uid, False)
            except Exception as e:
                print(f"[db] Error updating user status: {e}")
        
        rm = self.env("USER_REMOVE", "*", {"user_id": uid, "server_id": self.server_uuid})
        await self._broadcast(rm)
        print(f"[user] {uid} disconnected")
        if isinstance(uid, str):
            self._registering.discard(uid)

    async def _user_loop(self, link: Link):
        try:
            async for raw in link.ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                await self._on_user_msg(link, msg)
        except (ConnectionClosedOK, ConnectionClosedError):
            pass

    async def _on_user_msg(self, link: Link, msg: dict):
        if not self._dedup(msg):
            return

        # Proof of Possession: check the from field matches the link peer_id
        try:
            src = str(msg.get("from") or "")
            if (link.peer_id or "") and src and src != link.peer_id:
                err = self.env(
                    "ERROR",
                    link.peer_id,
                    {"code": "IDENTITY_MISMATCH", "detail": f"from={src}"},
                )
                await self._send(link, err)
                return
        except Exception:
            # on any error drop the frame without processing it
            return

        t = msg.get("type")
        if t in ("MSG_PRIVATE", "MSG_DIRECT"):
            await self._handle_msg_direct(msg)
        elif t == "MSG_PUBLIC_CHANNEL":
            await self._handle_msg_public_user(msg)
        elif t == "CTRL_LIST":
            await self._handle_ctrl_list(link)
        elif t == "CTRL_GET_PUB":
            await self._handle_ctrl_get_pub(link, msg)
        elif t in ("FILE_START", "FILE_CHUNK", "FILE_END"):
            await self._handle_file_message(msg)

    async def _presence_update(self, msg: dict):
        # verify server signature of presence update
        try:
            suuid = str(msg.get("from") or "")
            if not suuid:
                return
            pub = self.server_pubkeys.get(suuid)
            if not pub:
                # Unknown server, drop the presence update
                return
            if not rsa_pss_verify(pub, b64u_dec(msg.get("sig", "")), transport_sig_preimage(msg.get("payload", {}))):
                return
        except Exception:
            # If an error, reject presence update
            return
        pl = msg.get("payload", {})
        uid = pl.get("user_id")
        loc = pl.get("server_id")
        
        if msg.get("type") == "USER_ADVERTISE":
            if uid and loc:
                self.user_locations[uid] = loc
                if self.db:
                    try:
                        meta = pl.get("meta") or {}
                        pk = meta.get("pubkey") or pl.get("pubkey", "")
                        uu = meta.get("uuid") or pl.get("uuid")
                        if pk and uu:
                            self.db.add_or_update_user(uu, pk, loc, {"name": uid, "uuid": uu})
                    except Exception as e:
                        print(f"[db] Error persisting presence: {e}")
            
            meta = pl.get("meta") or {}
            pk = meta.get("pubkey") or pl.get("pubkey")
            if uid and pk:
                # No overwriting existing key
                if uid in self.user_pubkeys:
                    return
                # If a persisted key exists, accept only if it matches
                if self.db:
                    try:
                        db_pk_b64 = self.db.get_user_pubkey(uid)
                        if db_pk_b64 and db_pk_b64 != pk:
                            return
                    except Exception:
                        pass
                try:
                    self.user_pubkeys[uid] = rsa_pub_from_b64u(pk)
                except Exception:
                    pass
        else:
            if uid and self.user_locations.get(uid) == loc:
                self.user_locations.pop(uid, None)
                if self.db:
                    try:
                        self.db.update_user_status(uid, False)
                    except Exception:
                        pass

    async def _handle_ctrl_get_pub(self, link: Link, msg: dict):
        pl = msg.get("payload", {})
        who = pl.get("user_id")
        req_id = pl.get("req_id")
        
        if not who:
            resp = self.env("CTRL_PUBKEY", link.peer_id, {"ok": False, "error": "MISSING_USER_ID", "req_id": req_id or ""})
            await self._send(link, resp)
            return
        
        pub = self.user_pubkeys.get(who)
        if not pub and self.db:
            try:
                pk_b64 = self.db.get_user_pubkey(who)
                if pk_b64:
                    pub = rsa_pub_from_b64u(pk_b64)
                    self.user_pubkeys[who] = pub
            except Exception:
                pass
        
        if not pub:
            resp = self.env("CTRL_PUBKEY", link.peer_id, {"ok": False, "error": "USER_NOT_FOUND", "req_id": req_id or ""})
            await self._send(link, resp)
            return
        
        try:
            der = pub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            resp = self.env("CTRL_PUBKEY", link.peer_id, {"ok": True, "user_id": who, "pubkey": b64u(der), "req_id": req_id or ""})
            await self._send(link, resp)
        except Exception:
            resp = self.env("CTRL_PUBKEY", link.peer_id, {"ok": False, "error": "BAD_KEY", "req_id": req_id or ""})
            await self._send(link, resp)

    async def _handle_msg_direct(self, msg: dict):
        dst = msg.get("to")
        src = msg.get("from")
        pl = msg.get("payload", {})
        
        # Verify content signature using the pinned key of the sender
        try:
            pre = dm_content_preimage(pl.get("ciphertext", ""), src, dst, int(msg.get("ts", 0)))
            spub = self.user_pubkeys.get(src)
            if not spub and self.db:
                try:
                    pk_b64 = self.db.get_user_pubkey(src)
                    if pk_b64:
                        spub = rsa_pub_from_b64u(pk_b64)
                        self.user_pubkeys[src] = spub
                except Exception:
                    spub = None
            if not spub:
                if src in self.local_users:
                    err = self.env("ERROR", src, {"code": "UNKNOWN_SENDER_KEY", "detail": src})
                    await self._send(self.local_users[src], err)
                return
            if not rsa_pss_verify(spub, b64u_dec(pl.get("content_sig", "")), pre):
                if src in self.local_users:
                    err = self.env("ERROR", src, {"code": "BAD_CONTENT_SIG", "detail": "DM signature verification failed"})
                    await self._send(self.local_users[src], err)
                return
        except Exception:
            if src in self.local_users:
                err = self.env("ERROR", src, {"code": "BAD_CONTENT_SIG", "detail": "DM signature verification failed"})
                await self._send(self.local_users[src], err)
            return

        # STEP 1: If target_u in local_users → send directly (USER_DELIVER)
        if dst in self.local_users:
            env = self.env("USER_DELIVER", dst, {
                "ciphertext": pl.get("ciphertext"),
                "sender": src,
                # use the senders pinned pubkey
                "sender_pub": b64u(spub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)),
                "content_sig": pl.get("content_sig"),
                "msg_ts": msg.get("ts"),
            })
            

            await self._send(self.local_users[dst], env)
            print(f"[routing] Step 1: Delivered locally to {dst}")
            return
        
        # STEP 2: Otherwise, if user_locations[target_u] == "server_id" → send (SERVER_DELIVER) to servers[id]
        loc = self.user_locations.get(dst)
        
        # Check database if location not in memory
        if not loc and self.db:
            try:
                loc = self.db.get_user_location(dst)
                if loc:
                    self.user_locations[dst] = loc
            except Exception:
                pass
        
        if loc and loc in self.servers:
            env = self.env("SERVER_DELIVER", loc, {
                "user_id": dst,
                "ciphertext": pl.get("ciphertext"),
                "sender": src,
                # forward with the pinned sender pubkey
                "sender_pub": b64u(spub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)),
                "content_sig": pl.get("content_sig"),
                "msg_ts": msg.get("ts"),
            })
            await self._send(self.servers[loc], env)
            print(f"[routing] Step 2: Forwarded to server {loc} for user {dst}")
            return
        
        # STEP 3: Otherwise, emit ERROR(USER_NOT_FOUND) to the originating endpoint
        # Enhancement: Queue message if database is available (better than just error)
        if self.db:
            try:
                self.db.queue_message(
                    recipient_id=dst,
                    sender_id=src,
                    ciphertext=pl.get("ciphertext", ""),
                    iv="",
                    tag="",
                    wrapped_key="",
                    sender_pub=pl.get("sender_pub"),
                    content_sig=pl.get("content_sig")
                )
                print(f"[routing] Step 3: Queued message for offline user {dst}")
                
                # Notify sender that message was queued
                if src in self.local_users:
                    info = self.env("INFO", src, {"code": "MESSAGE_QUEUED", "detail": f"Message queued for offline user {dst}"})
                    await self._send(self.local_users[src], info)
                return
            except Exception as e:
                print(f"[routing] Error queuing message: {e}")
        
        # Final fallback: Send ERROR(USER_NOT_FOUND) to originating endpoint
        if src in self.local_users:
            err = self.env("ERROR", src, {"code": "USER_NOT_FOUND", "detail": f"User {dst} not found in network"})
            await self._send(self.local_users[src], err)
            print(f"[routing] Step 3: Sent USER_NOT_FOUND error to {src}")
                    
    async def _handle_peer_deliver(self, msg: dict):
        pl = msg.get("payload", {})
        uid = pl.get("user_id")
        if self.user_locations.get(uid) == self.server_uuid and uid in self.local_users:
            # Verify DM content using pinned key of the sender
            sender = pl.get("sender", "")
            try:
                ts = int(pl.get("msg_ts") or msg.get("ts") or 0)
                pre = dm_content_preimage(pl.get("ciphertext", ""), sender, uid, ts)
                senderpub = self.user_pubkeys.get(sender)
                if not senderpub and self.db:
                    try:
                        pk_b64 = self.db.get_user_pubkey(sender)
                        if pk_b64:
                            senderpub = rsa_pub_from_b64u(pk_b64)
                            self.user_pubkeys[sender] = senderpub
                    except Exception:
                        senderpub = None
                if not senderpub or not rsa_pss_verify(senderpub, b64u_dec(pl.get("content_sig", "")), pre):
                    return
                pinned_sender_pub_b64 = b64u(senderpub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            except Exception:
                return

            env = self.env("USER_DELIVER", uid, {
                "ciphertext": pl.get("ciphertext"),
                "iv": pl.get("iv"),
                "tag": pl.get("tag"),
                "wrapped_key": pl.get("wrapped_key"),
                "sender": sender,
                # use the pinned pubkey not the one in the payload
                "sender_pub": pinned_sender_pub_b64,
                "content_sig": pl.get("content_sig"),
                "msg_ts": pl.get("msg_ts") or msg.get("ts"),
            })
            await self._send(self.local_users[uid], env)

    async def _handle_server_deliver(self, msg: dict):
        pl = msg.get("payload", {})
        uid = pl.get("user_id")
        loc = self.user_locations.get(uid)

        try:
            sender = pl.get("sender", "")
            ts = int(pl.get("msg_ts") or msg.get("ts") or 0)
            pre = dm_content_preimage(pl.get("ciphertext", ""), sender, uid, ts)
            spub = self.user_pubkeys.get(sender)
            if not spub and self.db:
                try:
                    pk_b64 = self.db.get_user_pubkey(sender)
                    if pk_b64:
                        spub = rsa_pub_from_b64u(pk_b64)
                        self.user_pubkeys[sender] = spub
                except Exception:
                    spub = None
            if not spub:
                return
            if not rsa_pss_verify(spub, b64u_dec(pl.get("content_sig", "")), pre):
                return
        except Exception:
            return

        if loc == self.server_uuid and uid in self.local_users:
            env = self.env("USER_DELIVER", uid, {
                "ciphertext": pl.get("ciphertext"),
                "sender": pl.get("sender"),
                # use senders pinned pubkey
                "sender_pub": b64u(spub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)),
                "content_sig": pl.get("content_sig"),
                "msg_ts": pl.get("msg_ts") or msg.get("ts"),
            })
            await self._send(self.local_users[uid], env)
        elif loc and loc in self.servers:
            fwd = dict(msg)
            fwd["to"] = loc
            await self._send(self.servers[loc], fwd)

    async def _handle_msg_public_user(self, msg: dict):
        pl = msg.get("payload", {})
        sender = msg.get("from")
        channel = msg.get("to") or "public"
        if channel != "public":
            if sender in self.local_users:
                err = self.env("ERROR", sender, {"code": "CHANNEL_NOT_FOUND", "detail": channel})
                await self._send(self.local_users[sender], err)
            return
        try:
            pre = public_content_preimage(pl.get("ciphertext", ""), sender, int(msg.get("ts", 0)))
            spub = self.user_pubkeys.get(sender)
            if not spub and self.db:
                try:
                    pk_b64 = self.db.get_user_pubkey(sender)
                    if pk_b64:
                        spub = rsa_pub_from_b64u(pk_b64)
                        self.user_pubkeys[sender] = spub
                except Exception:
                    spub = None
            if not spub:
                err = self.env("ERROR", sender, {"code": "UNKNOWN_SENDER_KEY", "detail": sender})
                if sender in self.local_users:
                    await self._send(self.local_users[sender], err)
                return
            if not rsa_pss_verify(spub, b64u_dec(pl.get("content_sig", "")), pre):
                err = self.env("ERROR", sender, {"code": "BAD_CONTENT_SIG", "detail": "PUBLIC"})
                if sender in self.local_users:
                    await self._send(self.local_users[sender], err)
                return
        except Exception:
            if sender in self.local_users:
                err = self.env("ERROR", sender, {"code": "BAD_CONTENT_SIG", "detail": "PUBLIC"})
                await self._send(self.local_users[sender], err)
            return
        out_pl = {
            "ciphertext": pl.get("ciphertext"),
            "sender": sender,
            # use pinned sender pubkey
            "sender_pub": b64u(spub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)),
            "content_sig": pl.get("content_sig"),
            "msg_ts": msg.get("ts"),
            "channel": channel,
        }
        for uid, link in list(self.local_users.items()):
            if uid == sender:
                continue
            env = self.env("USER_DELIVER", uid, out_pl)
            await self._send(link, env)
        fwd = self.env("MSG_PUBLIC_CHANNEL", "*", out_pl)
        await self._broadcast(fwd)

    async def _handle_msg_public_server(self, msg: dict):
        pl = msg.get("payload", {})
        sender = pl.get("sender") or msg.get("from")
        channel = pl.get("channel") or "public"
        if channel != "public":
            return
        try:
            ts = int(pl.get("msg_ts") or msg.get("ts") or 0)
            pre = public_content_preimage(pl.get("ciphertext", ""), sender, ts)
            spub = self.user_pubkeys.get(sender)
            if not spub and self.db:
                try:
                    pk_b64 = self.db.get_user_pubkey(sender)
                    if pk_b64:
                        spub = rsa_pub_from_b64u(pk_b64)
                        self.user_pubkeys[sender] = spub
                except Exception:
                    spub = None
            if not spub:
                return
            if not rsa_pss_verify(spub, b64u_dec(pl.get("content_sig", "")), pre):
                return
        except Exception:
            return
        out_pl = {
            "ciphertext": pl.get("ciphertext"),
            "sender": sender,
            # use pinned sender pubkey
            "sender_pub": b64u(spub.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)),
            "content_sig": pl.get("content_sig"),
            "msg_ts": pl.get("msg_ts") or msg.get("ts"),
            "channel": channel,
        }
        for uid, link in list(self.local_users.items()):
            if uid == sender:
                continue
            env = self.env("USER_DELIVER", uid, out_pl)
            await self._send(link, env)

    async def _handle_file_message(self, msg: dict):
        t = msg.get("type")
        src = msg.get("from")
        dst = msg.get("to")
        pl = msg.get("payload", {})
        mode = pl.get("mode") or ("public" if (dst == "public" or dst == "*") else "dm")

        if mode == "public":
            # sned to all local users except sender
            for uid, link in list(self.local_users.items()):
                if uid == src:
                    continue
                env = self.env(t, uid, dict(pl))
                await self._send(link, env)
            # broadcast to other servers
            fwd = self.env(t, "*", dict(pl))
            await self._broadcast(fwd)
            return

        # DM mode
        if dst in self.local_users:
            env = self.env(t, dst, dict(pl))
            await self._send(self.local_users[dst], env)
            return

        loc = self.user_locations.get(dst)
        if loc and loc in self.servers:
            # wrap and forward to server
            out_pl = dict(pl)
            out_pl["user_id"] = dst
            env = self.env(
                {"FILE_START": "SERVER_FILE_START", "FILE_CHUNK": "SERVER_FILE_CHUNK", "FILE_END": "SERVER_FILE_END"}[t],
                loc,
                out_pl,
            )
            await self._send(self.servers[loc], env)
            return

        if src in self.local_users:
            err = self.env("ERROR", src, {"code": "USER_NOT_FOUND", "detail": f"User {dst} not connected to this server"})
            await self._send(self.local_users[src], err)

    async def _handle_public_add(self, msg: dict):
        pass

    async def _handle_public_updated(self, msg: dict):
        try:
            v = int(msg.get("payload", {}).get("version", 0))
            if v > 0 and v > self.public_version:
                self.public_version = v
        except Exception:
            pass

    async def _handle_public_key_share(self, msg: dict):
        pl = msg.get("payload", {})
        shares = pl.get("shares") or []
        creator_pub_b64 = pl.get("creator_pub", "")
        csig_b64 = pl.get("content_sig", "")
        try:
            cpub = rsa_pub_from_b64u(creator_pub_b64)
            if not rsa_pss_verify(cpub, b64u_dec(csig_b64), keyshare_preimage(shares, creator_pub_b64)):
                return
        except Exception:
            return
        for sh in shares:
            m = sh.get("member") or sh.get("member_id")
            if not m:
                continue
            if self.user_locations.get(m) == self.server_uuid and m in self.local_users:
                env = self.env("USER_PUBLIC_CHANNEL_KEY", m, {"channel": pl.get("channel") or "public", "shares": shares, "creator_pub": creator_pub_b64, "content_sig": csig_b64})
                await self._send(self.local_users[m], env)

    async def _handle_server_file(self, msg: dict):
        pl = msg.get("payload", {})
        uid = pl.get("user_id")
        if not uid:
            return
        out_pl = dict(pl)
        out_pl.pop("user_id", None)
        if self.user_locations.get(uid) == self.server_uuid and uid in self.local_users:
            t = msg.get("type", "")
            # SERVER_FILE_* -> FILE_*
            t_user = t.replace("SERVER_", "")
            env = self.env(t_user, uid, out_pl)
            await self._send(self.local_users[uid], env)

    async def _handle_peer_file_public(self, msg: dict):
        # share file to other local users
        pl = msg.get("payload", {})
        for uid, link in list(self.local_users.items()):
            env = self.env(msg.get("type"), uid, dict(pl))
            await self._send(link, env)

    async def _handle_ctrl_list(self, link: Link):
        online = sorted([u for u, l in self.user_locations.items() if l])
        resp = self.env("CTRL_LIST_RESP", link.peer_id, {"online": online})
        await self._send(link, resp)

    async def _on_ctrl_get_privstore(self, ws: WebSocketServerProtocol, msg: dict):
        pl = msg.get("payload", {})
        name = pl.get("user") or msg.get("from") or ""
        exists = False
        user_uuid = ""
        privkey_store = ""
        if self.db and name:
            try:
                row = self.db.get_user_by_name(name)
                if row and (row.get("user_id") or ""):
                    exists = True
                    user_uuid = row.get("user_id") or ""
                    privkey_store = row.get("privkey_store") or ""
            except Exception:
                pass
        resp = self.env("CTRL_PRIVSTORE", name or "user", {"exists": exists, "uuid": user_uuid, "privkey_store": privkey_store})
        try:
            await ws.send(json.dumps(resp))
        except Exception:
            pass
        try:
            await ws.close(code=1000)
        except Exception:
            pass

    async def _broadcast(self, obj: dict):
        for l in list(self.servers.values()):
            await self._send(l, obj)

    async def _send(self, link: Link, obj: dict):
        if obj.get("type") != "HEARTBEAT":
            print(obj)
        try:
            await link.ws.send(json.dumps(obj))
        except Exception:
            pass

    def _dedup(self, msg: dict) -> bool:
        try:
            h = hashlib.sha256()
            for k in ("type", "from", "to", "ts"):
                h.update(str(msg.get(k)).encode())
            h.update(json.dumps(msg.get("payload", {}), separators=(",", ":"), sort_keys=True).encode())
            key = h.hexdigest()
        except Exception:
            return True
        
        now = time.time()
        # Periodic cleanup of old entries
        if secrets.randbelow(128) == 0:
            for k, t in list(self.seen.items()):
                if now - t > self.seen_ttl:
                    self.seen.pop(k, None)
        
        # Check if message was already seen (prevents loops)
        if key in self.seen:
            print(f"[routing] Duplicate message detected - dropping to prevent loop")
            return False
        
        self.seen[key] = now
        return True

    async def heartbeat_loop(self):
        while not self._stop.is_set():
            await asyncio.sleep(self.hb_interval)
            now = time.time()
            
            for sid, link in list(self.servers.items()):
                try:
                    hb = self.env("HEARTBEAT", sid, {})
                    await self._send(link, hb)
                except Exception:
                    pass
            
            for sid, last in list(self.server_last_seen.items()):
                if now - last > self.hb_timeout:
                    link = self.servers.get(sid)
                    if link:
                        try:
                            await link.ws.close()
                        except Exception:
                            pass
                        self.servers.pop(sid, None)
                    
                    addr = self.server_addrs.get(sid)
                    if addr:
                        try:
                            await connect_peer(self, addr[0], int(addr[1]))
                        except Exception:
                            pass

async def connect_peer(node: Node, host: str, port: int):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        payload = {"host": node.host, "port": node.port, "pubkey": b64u(node.keys.pub_der)}
        hello = node.env("PEER_HELLO_LINK", "server_?", payload)
        print(hello)
        await ws.send(json.dumps(hello))
        
        link = Link(ws, f"server://{host}:{port}")
        node.servers[link.peer_id] = link
        
        async def reader():
            try:
                async for raw in ws:
                    msg = json.loads(raw)
                    await node._on_peer_msg(link, msg)
            except Exception:
                pass
        
        asyncio.create_task(reader())
        print(f"[peer] outbound linked -> {host}:{port}")
    except Exception as e:
        print(f"[peer] connect failed {host}:{port}: {e}")

async def bootstrap_join(node: Node, bootstrap: List[str]) -> List[dict]:
    results: List[dict] = []
    
    for spec in bootstrap:
        try:
            parts = spec.split(":")
            host = parts[0]
            port = int(parts[1])
            pinned_pub_b64 = parts[2] if len(parts) > 2 else None
            pinned_pub = rsa_pub_from_b64u(pinned_pub_b64) if pinned_pub_b64 else None
        except Exception as e:
            print(f"[bootstrap] ERROR: Failed to parse bootstrap entry '{spec}': {e}")
            if node.db:
                node.db._audit_log_direct("BOOTSTRAP_PARSE_ERROR", None, f"Failed to parse: {spec}", "ERROR")
            continue
        
        if pinned_pub is None or pinned_pub_b64 is None:
            print(f"[bootstrap] ERROR: No public key pinned for {host}:{port} - REJECTING")
            if node.db:
                node.db._audit_log_direct("BOOTSTRAP_NO_PIN", None, f"Rejected introducer {host}:{port} - no pinned key", "ERROR")
            continue
        
        print(f"[bootstrap] Attempting to join introducer at {host}:{port}")
        
        try:
            ws = await websockets.connect(f"ws://{host}:{port}", close_timeout=5)
        except Exception as e:
            print(f"[bootstrap] ERROR: Connection failed to {host}:{port}: {e}")
            if node.db:
                node.db._audit_log_direct("BOOTSTRAP_CONNECT_FAIL", None, f"Failed to connect to {host}:{port}: {e}", "WARNING")
            continue
        
        try:
            payload = {"host": node.host, "port": node.port, "pubkey": b64u(node.keys.pub_der)}
            env = node.env("SERVER_HELLO_JOIN", f"{host}:{port}", payload)
            await ws.send(json.dumps(env))
            
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            msg = json.loads(raw)
            
            if msg.get("type") != "SERVER_WELCOME":
                print(f"[bootstrap] ERROR: Unexpected message type: {msg.get('type')}")
                if node.db:
                    node.db._audit_log_direct("BOOTSTRAP_BAD_MSG", None, f"Wrong message type from {host}:{port}: {msg.get('type')}", "WARNING")
                await ws.close(code=1000)
                continue
            
            signature_valid = False
            try:
                sig_bytes = b64u_dec(msg.get("sig", ""))
                payload_bytes = transport_sig_preimage(msg.get("payload", {}))
                signature_valid = rsa_pss_verify(pinned_pub, sig_bytes, payload_bytes)
            except Exception as e:
                print(f"[bootstrap] ERROR: Signature verification failed for {host}:{port}: {e}")
                if node.db:
                    node.db._audit_log_direct("BOOTSTRAP_SIG_FAIL", None, f"Signature verification error for {host}:{port}: {str(e)}", "CRITICAL")
                signature_valid = False
            
            if not signature_valid:
                print(f"[bootstrap] CRITICAL: Invalid signature from {host}:{port} - REJECTING")
                if node.db:
                    node.db._audit_log_direct("BOOTSTRAP_INVALID_SIG", None, f"Invalid signature from introducer {host}:{port}", "CRITICAL")
                await ws.close(code=1002)
                continue
            
            print(f"[bootstrap] ✓ Signature verified for {host}:{port}")
            if node.db:
                node.db._audit_log_direct("BOOTSTRAP_SUCCESS", None, f"Successfully joined introducer {host}:{port}", "INFO")
            
            pl = msg.get("payload", {})
            assigned = pl.get("assigned_id")
            if isinstance(assigned, str) and assigned:
                try:
                    node.server_uuid = str(uuid.UUID(assigned))
                    print(f"[bootstrap] Assigned UUID: {node.server_uuid}")
                except Exception:
                    pass
            
            servers = pl.get("servers") or []
            for ent in servers:
                sid = ent.get("server_id")
                h = ent.get("host")
                p = ent.get("port")
                pk = ent.get("pubkey", "")
                
                if sid and h and p:
                    node.server_addrs[sid] = (h, int(p))
                    try:
                        if isinstance(pk, str) and pk:
                            node.server_pubkeys[sid] = rsa_pub_from_b64u(pk)
                            print(f"[bootstrap] Learned peer: {sid} at {h}:{p}")
                    except Exception as e:
                        print(f"[bootstrap] WARNING: Failed to parse pubkey for {sid}: {e}")
                    results.append(ent)
            
            await ws.close(code=1000)
            break
            
        except asyncio.TimeoutError:
            print(f"[bootstrap] ERROR: Timeout waiting for response from {host}:{port}")
            if node.db:
                node.db._audit_log_direct("BOOTSTRAP_TIMEOUT", None, f"Timeout from {host}:{port}", "WARNING")
            try:
                await ws.close(code=1000)
            except Exception:
                pass
            continue
        except Exception as e:
            print(f"[bootstrap] ERROR: Unexpected error with {host}:{port}: {e}")
            if node.db:
                node.db._audit_log_direct("BOOTSTRAP_ERROR", None, f"Error from {host}:{port}: {str(e)}", "ERROR")
            try:
                await ws.close(code=1000)
            except Exception:
                pass
            continue
    
    if not results:
        print("[bootstrap] CRITICAL: No introducer could be reached or verified")
        if node.db:
            node.db._audit_log_direct("BOOTSTRAP_TOTAL_FAIL", None, "Failed to bootstrap from any introducer", "CRITICAL")
    
    return results

def load_bootstrap_file(path: str) -> List[str]:
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception:
        return out
    
    in_list = False
    cur: Dict[str, Any] = {}
    
    def flush():
        if cur.get("host") and cur.get("port"):
            host = str(cur.get("host")).strip()
            port = str(cur.get("port")).strip()
            pk = str(cur.get("pubkey", "")).strip()
            spec = f"{host}:{port}:{pk}" if pk else f"{host}:{port}"
            out.append(spec)
    
    for raw in lines:
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        
        s = line.strip()
        if not in_list:
            if s.startswith("bootstrap_servers"):
                in_list = True
            continue
        
        if s.startswith("-"):
            if cur:
                flush()
                cur = {}
            s = s[1:].strip()
            if s:
                if ":" in s:
                    k, v = s.split(":", 1)
                    v = v.strip().strip('"').strip("'")
                    if k.strip() == "port":
                        try:
                            v = int(v)
                        except Exception:
                            pass
                    cur[k.strip()] = v
            continue
        
        if ":" in s:
            k, v = s.split(":", 1)
            v = v.strip().strip('"').strip("'")
            if k.strip() == "port":
                try:
                    v = int(v)
                except Exception:
                    pass
            cur[k.strip()] = v
    
    if cur:
        flush()
    
    return out

def load_or_create_privkey(path: str) -> rsa.RSAPrivateKey:
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_private_key(data, password=None)
    except Exception:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        try:
            pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(path, "wb") as f:
                f.write(pem)
        except Exception:
            pass
        return priv

def _ensure_uuid(s: str | None) -> str:
    try:
        if s:
            return str(uuid.UUID(s))
    except Exception:
        pass
    new_id = str(uuid.uuid4())
    try:
        print(f"[id] Assigned new server UUID: {new_id}")
    except Exception:
        pass
    return new_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uuid", required=False, help="server UUID (defaults to UUIDv4)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--peer", help="host:port of existing server to link", action="append")
    ap.add_argument("--bootstrap", help="introducer entries host:port:pubkey", action="append")
    ap.add_argument("--bootstrap-file", help="YAML file of trusted introducers")
    ap.add_argument("--key-file", help="PEM file for RSA keypair")
    ap.add_argument("--print-pub", help="print base64url public key and exit", action="store_true")
    ap.add_argument("--introducer", help="run as introducer", action="store_true")
    ap.add_argument("--no-db", help="disable database persistence", action="store_true")
    args = ap.parse_args()

    server_uuid = _ensure_uuid(getattr(args, "uuid", None))
    node = Node(server_uuid, args.host, args.port, introducer=args.introducer, use_db=not args.no_db)
    
    if args.key_file:
        try:
            node.keys = RSAKeys(load_or_create_privkey(args.key_file))
        except Exception:
            pass
    
    if args.print_pub or args.introducer:
        try:
            print(f"[pubkey] {b64u(node.keys.pub_der)}")
            if args.print_pub:
                return
        except Exception:
            pass

    async def runner():
        async def dial_all():
            asyncio.create_task(node.heartbeat_loop())
            await asyncio.sleep(0.2)
            
            if node.is_introducer:
                return
            
            entries: List[str] = []
            if args.bootstrap_file:
                entries.extend(load_bootstrap_file(args.bootstrap_file))
            else:
                for fn in ("bootstrap.yaml", "bootstrap.yml"):
                    if os.path.exists(fn):
                        entries.extend(load_bootstrap_file(fn))
                        break
            
            if args.bootstrap:
                entries.extend(args.bootstrap)
            
            if entries:
                lst = await bootstrap_join(node, entries)
                if not lst:
                    print("[bootstrap] no introducer reachable; exiting")
                    node.stop()
                    return
                
                for ent in lst:
                    sid = ent.get("server_id")
                    h = ent.get("host")
                    p = ent.get("port")
                    if sid and h and p and sid != node.server_uuid:
                        await connect_peer(node, h, int(p))
                
                await asyncio.sleep(0.3)
                ann = node.env("SERVER_ANNOUNCE", "*", {"host": node.host, "port": node.port, "pubkey": b64u(node.keys.pub_der)})
                await node._broadcast(ann)
            
            if args.peer:
                for hp in args.peer:
                    h, p = hp.split(":", 1)
                    await connect_peer(node, h, int(p))
        
        await asyncio.gather(node.start(), dial_all())

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
