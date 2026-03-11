'''
client.py — VULNERABLE VERSION: Contains backdoors as per assignment requirements. 
Python 3.11+
Implements SOCP v1.3 Protocol
'''
import asyncio, json, time, argparse, base64, uuid, os
import hashlib
import getpass
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def rsa_pub_from_b64u(b: str):
    return serialization.load_der_public_key(b64u_dec(b))

def rsa_pss_sign(priv, data: bytes) -> bytes:
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

def dm_content_preimage(ciphertext: bytes, from_id: str, to_id: str, ts: int) -> bytes:
    h = hashlib.sha256()
    h.update(ciphertext)
    h.update(from_id.encode())
    h.update(to_id.encode())
    h.update(str(ts).encode())
    return h.digest()

def public_content_preimage(ciphertext: bytes, from_id: str, ts: int) -> bytes:
    h = hashlib.sha256()
    h.update(ciphertext)
    h.update(from_id.encode())
    h.update(str(ts).encode())
    return h.digest()

class Client:
    def __init__(self, host: str, port: int, user_id: str):
        self.host, self.port, self.user_id = host, port, user_id
        self.user_uuid = str(uuid.uuid4())
        self.keys = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.pub_b64u = b64u(self.keys.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        self._waiters = {}
        self._priv_store_local = None
        # Pinned list of peer_id ----> pubkey_b64u
        self._peer_pins: dict[str, str] = {}
        # file transfer state keeping
        self._recv_files = {}
        self._downloads_dir = os.path.join(os.getcwd(), "downloads")
        try:
            os.makedirs(self._downloads_dir, exist_ok=True)
        except Exception:
            pass

    def _unwrap_privkey(self, blob: str, password: str):
        try:
            parts = blob.split("$")
            if len(parts) != 8 or parts[0] != 'scrypt' or parts[5] != 'gcm':
                raise ValueError("bad blob format")
            logN = int(parts[1]); r = int(parts[2]); p = int(parts[3])
            salt = b64u_dec(parts[4])
            nonce = b64u_dec(parts[6])
            ct = b64u_dec(parts[7])
            kdf = Scrypt(salt=salt, length=32, n=2**logN, r=r, p=p)
            key = kdf.derive(password.encode())
            aesgcm = AESGCM(key)
            pem = aesgcm.decrypt(nonce, ct, None)
            return serialization.load_pem_private_key(pem, password=None)
        except Exception as e:
            raise ValueError(f"decrypt failed: {e}")

    # key lives in memory, fetch wrapped key from server when needed
    def _init_keys_from_privstore(self, password: str, privstore: str | None):
        if privstore:
            priv = self._unwrap_privkey(privstore, password)
            self.keys = priv
            self.pub_b64u = b64u(self.keys.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            # rotate wrapping for sending to server
            self._priv_store_local = self._wrap_privkey(password)
            return
        # no stored key, generate fresh pair
        self.keys = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.pub_b64u = b64u(self.keys.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        self._priv_store_local = self._wrap_privkey(password)

    async def _fetch_privstore(self) -> tuple[bool, str, str]:
        uri = f"ws://{self.host}:{self.port}"
        try:
            async with await self._connect_with_retries(uri) as ws_probe:
                req = {
                    "type": "CTRL_GET_PRIVSTORE",
                    "from": self.user_id,
                    "to": "server_*",
                    "ts": int(time.time() * 1000),
                    "payload": {"user": self.user_id},
                    "sig": "",
                }
                await ws_probe.send(json.dumps(req))
                raw = await asyncio.wait_for(ws_probe.recv(), timeout=3.0)
                try:
                    resp = json.loads(raw)
                except Exception:
                    return (False, "", "")
                if resp.get("type") == "CTRL_PRIVSTORE":
                    pl = resp.get("payload", {})
                    return (bool(pl.get("exists")), pl.get("uuid") or "", pl.get("privkey_store") or "")
        except Exception:
            pass
        return (False, "", "")

    def _derive_key(self, password: str, salt: bytes, length: int = 32) -> bytes:
        kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())

    def _wrap_privkey(self, password: str) -> str:
        # Encrypt the client's PKCS#8 private key with a key derived from the user's password using scrypt + AES-GCM.
        pem = self.keys.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, pem, None)
        return f"scrypt$14$8$1${b64u(salt)}$gcm${b64u(nonce)}${b64u(ct)}"

    def _pake_verifier(self, password: str) -> str:
        # PAKE verifier: scrypt-derived key with deterministic salt per username. Format: pake$scrypt$14$8$1$<salt_b64u>$<verifier_b64u>
        import hashlib
        salt = hashlib.sha256(f"SOCP-PAKE::{self.user_id}".encode()).digest()[:16]
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(password.encode())
        return f"pake$scrypt$14$8$1${b64u(salt)}${b64u(key)}"
    
    def user_hello(self, pake_password: str | None = None, privkey_store: str | None = None):
        payload = {
            "type": "USER_HELLO",
            "from": self.user_id,
            "to": "server_*",
            "ts": int(time.time() * 1000),
            "payload": {"client": "cli-min", "pubkey": self.pub_b64u, "enc_pubkey": self.pub_b64u, "name": self.user_id, "uuid": self.user_uuid},
            "sig": "",
        }
        if pake_password:
            payload["payload"]["pake_password"] = pake_password
        if privkey_store:
            payload["payload"]["privkey_store"] = privkey_store
        return payload

    def make_dm(self, to_user: str, recip_pub_b64u: str, text: str):
        recip_pub = rsa_pub_from_b64u(recip_pub_b64u)
        ciphertext = recip_pub.encrypt(
            text.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        ts = int(time.time() * 1000)
        pre = dm_content_preimage(ciphertext, self.user_id, to_user, ts)
        content_sig = b64u(rsa_pss_sign(self.keys, pre))
        return {
            "type": "MSG_PRIVATE",
            "from": self.user_id,
            "to": to_user,
            "ts": ts,
            "payload": {
                "ciphertext": b64u(ciphertext),
                "sender_pub": self.pub_b64u,
                "content_sig": content_sig,
            },
            "sig": "",
        }

    def make_public(self, channel: str, text: str):
        ciphertext = text.encode()
        ts = int(time.time() * 1000)
        pre = public_content_preimage(ciphertext, self.user_id, ts)
        content_sig = b64u(rsa_pss_sign(self.keys, pre))
        return {
            "type": "MSG_PUBLIC_CHANNEL",
            "from": self.user_id,
            "to": channel,
            "ts": ts,
            "payload": {
                "ciphertext": b64u(ciphertext),
                "sender_pub": self.pub_b64u,
                "content_sig": content_sig,
            },
            "sig": "",
        }

    # File Transfer helpers functions
    def _file_compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _file_chunk_plain(self, data: bytes, max_size: int = 400):
        for i in range(0, len(data), max_size):
            yield data[i:i + max_size]

    async def _send_file_dm(self, ws, to_user: str, path: str):
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except Exception as e:
            print(f"[file] open failed: {e}")
            return
        name = os.path.basename(path)
        fid = str(uuid.uuid4())
        size = len(raw)
        sha_hex = self._file_compute_sha256(raw)
        # get recipients pubkey
        pub = await self._get_pubkey(ws, to_user)
        if not pub:
            print(f"recipient key not found for {to_user}")
            return
        # send FILE_START (manifest)
        start = {
            "type": "FILE_START",
            "from": self.user_id,
            "to": to_user,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": fid, "name": name, "size": size, "sha256": sha_hex, "mode": "dm"},
            "sig": "",
        }
        await ws.send(json.dumps(start))
        # For each chunk, encrypt with recipient pubkey and send FILE_CHUNK
        recip_pub = rsa_pub_from_b64u(pub)
        idx = 0
        for chunk in self._file_chunk_plain(raw, 400):
            try:
                ct = recip_pub.encrypt(
                    chunk,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                )
            except Exception as e:
                print(f"[file] encrypt chunk {idx} failed: {e}")
                return
            frame = {
                "type": "FILE_CHUNK",
                "from": self.user_id,
                "to": to_user,
                "ts": int(time.time() * 1000),
                "payload": {"file_id": fid, "index": idx, "ciphertext": b64u(ct)},
                "sig": "",
            }
            await ws.send(json.dumps(frame))
            idx += 1
        end = {
            "type": "FILE_END",
            "from": self.user_id,
            "to": to_user,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": fid},
            "sig": "",
        }
        await ws.send(json.dumps(end))
        print(f"[file] sent {name} ({size} bytes) to {to_user}")

    async def _send_file_public(self, ws, channel: str, path: str):
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except Exception as e:
            print(f"[file] open failed: {e}")
            return
        name = os.path.basename(path)
        fid = str(uuid.uuid4())
        size = len(raw)
        sha_hex = self._file_compute_sha256(raw)
        start = {
            "type": "FILE_START",
            "from": self.user_id,
            "to": channel,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": fid, "name": name, "size": size, "sha256": sha_hex, "mode": "public"},
            "sig": "",
        }
        await ws.send(json.dumps(start))
        # currently uses no encryption for public files
        idx = 0
        for chunk in self._file_chunk_plain(raw, 2048):
            frame = {
                "type": "FILE_CHUNK",
                "from": self.user_id,
                "to": channel,
                "ts": int(time.time() * 1000),
                "payload": {"file_id": fid, "index": idx, "ciphertext": b64u(chunk)},
                "sig": "",
            }
            await ws.send(json.dumps(frame))
            idx += 1
        end = {
            "type": "FILE_END",
            "from": self.user_id,
            "to": channel,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": fid},
            "sig": "",
        }
        await ws.send(json.dumps(end))
        print(f"[file] sent {name} ({size} bytes) to channel {channel}")

    async def _get_pubkey(self, ws, user: str, timeout: float = 5.0):
        req_id = str(uuid.uuid4())
        await ws.send(json.dumps({
            "type": "CTRL_GET_PUB",
            "from": self.user_id,
            "to": "server_*",
            "ts": int(time.time()*1000),
            "payload": {"user_id": user, "req_id": req_id},
            "sig": ""
        }))
        fut = asyncio.get_running_loop().create_future()
        self._waiters[req_id] = fut
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._waiters.pop(req_id, None)

    async def _connect_with_retries(self, uri: str):
        last_err = None
        for _ in range(20):
            try:
                return await websockets.connect(uri)
            except OSError as e:
                last_err = e
                await asyncio.sleep(0.25)
        raise last_err

    async def run(self):
        # Fetch server stored privkey_store
        exists, known_uuid, stored_priv = await self._fetch_privstore()

        if exists:
            print("Existing user found. Enter Password.")
            pw = getpass.getpass("Password: ")
            if known_uuid:
                self.user_uuid = known_uuid
        else:
            while True:
                pw1 = getpass.getpass("Create password: ")
                pw2 = getpass.getpass("Confirm password: ")
                if pw1 == pw2:
                    pw = pw1
                    break
                print("Passwords do not match. Try again.")
        # Initialize RSA keys in memory from server privstore
        self._init_keys_from_privstore(pw, stored_priv if exists else None)
        print(f"Assigned uuid: {self.user_uuid}")

        priv_store = self._priv_store_local
        uri = f"ws://{self.host}:{self.port}"
        async with await self._connect_with_retries(uri) as ws:
            pake = self._pake_verifier(pw)
            await ws.send(json.dumps(self.user_hello(pake_password=pake, privkey_store=priv_store)))
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                try:
                    first = json.loads(raw)
                except Exception:
                    first = {}
                if first.get("type") == "ERROR" and (first.get("payload", {}) or {}).get("code") == "NAME_IN_USE":
                    print(f"[error] NAME_IN_USE: {self.user_id}")
                    await ws.close()
                    return
                if first.get("type") == "AUTH_CHALLENGE":
                    ch = (first.get("payload", {}) or {}).get("challenge") or ""
                    try:
                        challenge = b64u_dec(ch)
                        sig = rsa_pss_sign(self.keys, challenge)
                        proof = {
                            "type": "AUTH_PROOF",
                            "from": self.user_id,
                            "to": "server_*",
                            "ts": int(time.time() * 1000),
                            "payload": {"challenge": ch, "signature": b64u(sig)},
                            "sig": "",
                        }
                        await ws.send(json.dumps(proof))
                    except Exception as e:
                        print(f"[error] AUTH failed to sign: {e}")
                        await ws.close()
                        return
            except asyncio.TimeoutError:
                pass
            print(f"[cli:{self.user_id}] connected. Commands: /mykey | /list | /tell <user> <text...> | /all <message> |/quit")

            async def rx():
                try:
                    async for raw in ws:
                        msg = json.loads(raw)
                        t = msg.get("type")
                        if t in ("FILE_START", "FILE_CHUNK", "FILE_END"):
                            pl = msg.get("payload", {})
                            sender = msg.get("from")
                            if t == "FILE_START":
                                fid = pl.get("file_id")
                                if not fid:
                                    continue
                                self._recv_files[fid] = {
                                    "from": sender,
                                    "name": pl.get("name") or f"file_{fid}",
                                    "size": int(pl.get("size") or 0),
                                    "sha256": (pl.get("sha256") or "").lower(),
                                    "mode": pl.get("mode") or "dm",
                                    "chunks": {},
                                }
                                print(f"\n[file] start from {sender}: {self._recv_files[fid]['name']} ({self._recv_files[fid]['size']} bytes)\n> ", end="")
                            elif t == "FILE_CHUNK":
                                fid = pl.get("file_id")
                                idx = pl.get("index")
                                ct_b64 = pl.get("ciphertext") or ""
                                if fid is None or idx is None:
                                    continue
                                state = self._recv_files.get(fid)
                                if not state:
                                    self._recv_files[fid] = {"from": sender, "name": f"file_{fid}", "size": 0, "sha256": "", "mode": "dm", "chunks": {}}
                                    state = self._recv_files[fid]
                                try:
                                    data = b64u_dec(ct_b64)
                                    if (state.get("mode") or "dm") == "dm":
                                        data = self.keys.decrypt(
                                            data,
                                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                                        )
                                    state["chunks"][int(idx)] = data
                                except Exception as e:
                                    print(f"\n[file] chunk {idx} decrypt/parse failed: {e}\n> ", end="")
                            elif t == "FILE_END":
                                fid = pl.get("file_id")
                                state = self._recv_files.get(fid)
                                if not state:
                                    print(f"\n[file] end: unknown file_id {fid}\n> ", end="")
                                    continue
                                # Aassemble and verify the file chunks
                                chunks = state.get("chunks", {})
                                if not chunks:
                                    print(f"\n[file] no data received for {state['name']}\n> ", end="")
                                    self._recv_files.pop(fid, None)
                                    continue
                                data = b"".join(chunks[i] for i in sorted(chunks.keys()))
                                ok_size = (state.get("size") == 0) or (len(data) == state.get("size"))
                                sha_hex = hashlib.sha256(data).hexdigest()
                                ok_hash = (not state.get("sha256")) or (sha_hex == state.get("sha256"))
                                # save the assembled file to the out_path
                                out_path = os.path.join(self._downloads_dir, f"{fid}_{state.get('name')}")
                                try:
                                    with open(out_path, "wb") as f:
                                        f.write(data)
                                    print(f"\n[file] saved to {out_path} (size_ok={ok_size}, hash_ok={ok_hash})\n> ", end="")
                                except Exception as e:
                                    print(f"\n[file] save failed: {e}\n> ", end="")
                                self._recv_files.pop(fid, None)
                            continue
                        if t == "USER_DELIVER":
                            pl = msg.get("payload", {})
                            sender = pl.get("sender")
                            cipher_b64 = pl.get("ciphertext")
                            sig_b64 = pl.get("content_sig")
                            sender_pub_b64 = pl.get("sender_pub")
                            msg_ts = pl.get("msg_ts") or msg.get("ts")
                            # try:
                            #     print(f"\n[debug] recv USER_DELIVER from {sender} ts={msg_ts}\n> ", end="")
                            # except Exception:
                            #     pass

                            if not sender or not cipher_b64 or not sig_b64 or not sender_pub_b64:
                                # print(f"\n[debug] invalid fields sender={bool(sender)} cipher={bool(cipher_b64)} sig={bool(sig_b64)} sender_pub={bool(sender_pub_b64)}\n> ", end="")
                                print("\n[dm] invalid payload\n> ", end="")
                                continue
                            try:
                                ciphertext = b64u_dec(cipher_b64)
                                # First key seen of sender is pinned, subsequent messages must match - Spoofing prevention
                                pinned = self._peer_pins.get(sender)
                                if pinned is None:
                                    self._peer_pins[sender] = sender_pub_b64
                                    pinned = sender_pub_b64
                                if sender_pub_b64 != pinned:
                                    print("\n[dm] key mismatch for sender; dropping\n> ", end="")
                                    continue
                                sender_pub = rsa_pub_from_b64u(pinned)
                                sig = b64u_dec(sig_b64)
                                ts_int = int(msg_ts)
                            except Exception as e:
                                # try:
                                #     print(f"\n[debug] envelope parse error: {e}\n> ", end="")
                                # except Exception:
                                #     pass
                                print(f"\n[dm] invalid envelope: {e}\n> ", end="")
                                continue
                            if pl.get("channel"):
                                pre = public_content_preimage(ciphertext, sender, ts_int)
                                if not rsa_pss_verify(sender_pub, sig, pre):
                                    # print("\n[debug] signature verification failed (channel)\n> ", end="")
                                    print("\n[chan] signature verification failed\n> ", end="")
                                    continue
                                try:
                                    print(f"\n[channel:{pl.get('channel')}] {sender}: {ciphertext.decode(errors='ignore')}\n> ", end="")
                                except Exception as e:
                                    print(f"\n[chan] display failed: {e}\n> ", end="")
                            else:
                                pre = dm_content_preimage(ciphertext, sender, self.user_id, ts_int)
                                if not rsa_pss_verify(sender_pub, sig, pre):
                                    # print("\n[debug] signature verification failed (dm)\n> ", end="")
                                    print("\n[dm] signature verification failed\n> ", end="")
                                    continue
                                try:
                                    pt = self.keys.decrypt(
                                        ciphertext,
                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                                    )
                                    # try:
                                    #     print(f"\n[debug] decrypt ok bytes={len(pt)}\n> ", end="")
                                    # except Exception:
                                    #     pass
                                    print(f"\n[dm] {sender}: {pt.decode(errors='ignore')}\n> ", end="")
                                except Exception as e:
                                    # try:
                                    #     print(f"\n[debug] decrypt error: {e}\n> ", end="")
                                    # except Exception:
                                    #     pass
                                    print(f"\n[dm] decrypt failed: {e}\n> ", end="")
                        elif t == "CTRL_LIST_RESP":
                            online = msg.get("payload", {}).get("online", [])
                            print(f"\n[online] {', '.join(online)}\n> ", end="")
                        elif t == "ERROR":
                            pl = msg.get("payload", {})
                            print(f"\n[error] {pl.get('code','ERROR')}: {pl.get('detail','')}\n> ", end="")
                        elif t == "CTRL_PUBKEY":
                            pl = msg.get("payload", {})
                            req_id = pl.get("req_id")
                            if req_id and req_id in self._waiters:
                                self._waiters[req_id].set_result(pl.get("pubkey") if pl.get("ok") else None)
                except Exception as e:
                    pass
                    
            rxt = asyncio.create_task(rx())
            loop = asyncio.get_running_loop()
            while True:
                line = await loop.run_in_executor(None, input, "> ")
                if not line:
                    continue
                if line.strip() in ("/quit", ":q"):
                    break
                if line.strip() == "/mykey":
                    print(self.pub_b64u); continue
                if line.strip().startswith("/list"):
                    tokens = line.strip().split()
                    if len(tokens) >= 2 and tokens[1] == "-channels":
                        print("\n[channels] public\n> ", end=""); continue
                    await ws.send(json.dumps({"type":"CTRL_LIST","from":self.user_id,"to":"server_*","ts":int(time.time()*1000),"payload":{},"sig":""}))
                    continue
                if line.startswith("/all "):
                    text = line[5:].strip()
                    if not text:
                        print("usage: /all <message>")
                        continue
                    env = self.make_public("public", text)
                    await ws.send(json.dumps(env))
                    continue
                if line.startswith("/tell "):
                    try:
                        parts = line.split(" ")
                        if len(parts) >= 3 and parts[1] == "-channel":
                            if len(parts) < 4:
                                print("usage: /tell -channel <name> <text...>"); continue
                            channel = parts[2]
                            text = " ".join(parts[3:]).strip()
                            if not text:
                                print("usage: /tell -channel <name> <text...>"); continue
                            if channel != "public":
                                print(f"[error] CHANNEL_NOT_FOUND: {channel}"); continue
                            env = self.make_public(channel, text)
                            await ws.send(json.dumps(env))
                        else:
                            _, to, *text = parts
                            text = " ".join(text).strip()
                            if not text:
                                print("usage: /tell <user> <text...>"); continue
                            pub = await self._get_pubkey(ws, to)
                            if not pub:
                                print(f"recipient key not found for {to}"); continue
                            await ws.send(json.dumps(self.make_dm(to, pub, text)))
                    except ValueError:
                        print("usage: /tell <user> <text...>")
                    continue
                if line.startswith("/file "):
                    try:
                        parts = line.split(" ")
                        # /file -channel <name> <path>
                        if len(parts) >= 4 and parts[1] == "-channel":
                            channel = parts[2]
                            path = " ".join(parts[3:]).strip()
                            if not os.path.isfile(path):
                                print("usage: /file -channel <name> <path>"); continue
                            await self._send_file_public(ws, channel, path)
                        else:
                            # /file <user> <path>
                            if len(parts) < 3:
                                print("usage: /file <user> <path>"); continue
                            to = parts[1]
                            path = " ".join(parts[2:]).strip()
                            if not os.path.isfile(path):
                                print("usage: /file <user> <path>"); continue
                            await self._send_file_dm(ws, to, path)
                    except Exception as e:
                        print(f"[file] error: {e}")
                    continue
                print("unknown command")
            rxt.cancel()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True, help="username")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    args = ap.parse_args()
    asyncio.run(Client(args.host, args.port, args.user).run())

if __name__ == "__main__":
    main()
