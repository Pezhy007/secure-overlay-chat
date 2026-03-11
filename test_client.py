import asyncio, json, base64, time
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "="*((4 - len(s)%4)%4))

def dm_content_preimage(ciphertext_b64: str, from_id: str, to_id: str, ts: int) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    try:
        h.update(b64u_dec(ciphertext_b64 or ""))
    except Exception:
        h.update((ciphertext_b64 or "").encode())
    h.update(from_id.encode()); h.update(to_id.encode()); h.update(str(ts).encode())
    return h.finalize()

async def login_user(host: str, port: int, user_id: str, key: rsa.RSAPrivateKey):
    uri = f"ws://{host}:{port}"
    ws = await websockets.connect(uri)

    # USER_HELLO
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hello = {
        "type": "USER_HELLO",
        "from": user_id,
        "to": f"{host}:{port}",
        "ts": int(time.time()*1000),
        "payload": {"pubkey": b64u(pub_der)}
    }
    await ws.send(json.dumps(hello))

    # AUTH_CHALLENGE
    msg = json.loads(await ws.recv())
    assert msg["type"] == "AUTH_CHALLENGE"
    ch_b64 = msg["payload"]["challenge"]

    sig = key.sign(
        b64u_dec(ch_b64),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256()
    )
    proof = {
        "type": "AUTH_PROOF",
        "from": user_id,
        "to": msg["from"],
        "ts": int(time.time()*1000),
        "payload": {"challenge": ch_b64, "signature": b64u(sig)}
    }
    await ws.send(json.dumps(proof))
    print(f"[client:{user_id}] logged in on {host}:{port}")

    # background receiver to print deliveries
    async def recv_loop():
        async for raw in ws:
            try:
                env = json.loads(raw)
                t = env.get("type")
                if t == "USER_DELIVER":
                    pl = env["payload"]
                    print(f"[client:{user_id}] USER_DELIVER from={pl.get('sender')} ct={pl.get('ciphertext')}")
                elif t in ("INFO","ERROR"):
                    print(f"[client:{user_id}] {t} {env.get('payload')}")
            except Exception:
                pass
    asyncio.create_task(recv_loop())
    return ws

def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)

async def send_dm(ws, sender_id, sender_key, to_id, plaintext="hi"):
    ct = b64u(plaintext.encode())  # pretend ciphertext for testing
    ts = int(time.time()*1000)
    pre = dm_content_preimage(ct, sender_id, to_id, ts)
    sig = sender_key.sign(pre, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    msg = {
        "type": "MSG_DIRECT",
        "from": sender_id,
        "to": to_id,
        "ts": ts,
        "payload": {
            "ciphertext": ct,
            "sender_pub": b64u(sender_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )),
            "content_sig": b64u(sig),
        }
    }
    await ws.send(json.dumps(msg))

async def main():
    # generate keys
    alice_k = gen_key()
    bob_k   = gen_key()
    char_k  = gen_key()

    # login users on their servers (A,B,C)
    alice_ws = await login_user("127.0.0.1", 9001, "alice", alice_k)   # on A
    bob_ws   = await login_user("127.0.0.1", 9002, "bob", bob_k)       # on B
    char_ws  = await login_user("127.0.0.1", 9003, "charlie", char_k)  # on C

    await asyncio.sleep(1.0)  # let presence propagate

    print("\n# T1 local: alice->alice")
    await send_dm(alice_ws, "alice", alice_k, "alice", "local-echo")

    print("\n# T2 cross: alice@A -> bob@B")
    await send_dm(alice_ws, "alice", alice_k, "bob", "hello-bob")

    print("\n# T3 cross: bob@B -> charlie@C")
    await send_dm(bob_ws, "bob", bob_k, "charlie", "hi-charlie")

    print("\n# T4 offline: alice -> dave (should queue or ERROR)")
    await send_dm(alice_ws, "alice", alice_k, "dave", "you there?")

    await asyncio.sleep(3)

if __name__ == "__main__":
    asyncio.run(main())
