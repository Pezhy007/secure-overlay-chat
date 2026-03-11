import sqlite3
import json
import threading
import hashlib
import secrets
import os
import stat
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("[WARNING] cryptography library not available - database encryption disabled")


class ServerDatabase:
    MAX_QUEUED_MESSAGES_PER_USER = 1000
    MESSAGE_EXPIRY_DAYS = 30
    MAX_MESSAGE_ID_BATCH = 500

    def __init__(self, db_path: str = "socp_server.db", encryption_key: Optional[str] = None):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.encryption_key = encryption_key
        self._set_secure_permissions()

        if encryption_key and ENCRYPTION_AVAILABLE:
            self._setup_encryption(encryption_key)
        else:
            self.cipher = None
            if encryption_key and not ENCRYPTION_AVAILABLE:
                print("[WARNING] Encryption key provided but cryptography library not available")

        self._init_database()
        self._cleanup_expired_messages()

    def _set_secure_permissions(self):
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            print(f"[security] WARNING: Could not set secure permissions: {e}")

    def _setup_encryption(self, password: str):
        import base64
        try:
            salt_path = self.db_path + ".salt"
            if os.path.exists(salt_path):
                with open(salt_path, "rb") as f:
                    salt = f.read()
            else:
                salt = secrets.token_bytes(16)
                with open(salt_path, "wb") as f:
                    f.write(salt)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
                backend=default_backend()
            )
            self.encryption_key_bytes = kdf.derive(password.encode())
            print("[security] Database field-level encryption enabled")
        except Exception as e:
            print(f"[security] Failed to setup encryption: {e}")
            self.cipher = None

    def _encrypt_data(self, data: str) -> str:
        if not hasattr(self, 'encryption_key_bytes'):
            return data
        try:
            iv = secrets.token_bytes(12)
            cipher = Cipher(
                algorithms.AES(self.encryption_key_bytes),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            import base64
            encrypted = base64.b64encode(iv + encryptor.tag + ciphertext).decode()
            return f"ENC:{encrypted}"
        except Exception as e:
            print(f"[security] Encryption failed: {e}")
            return data

    def _decrypt_data(self, data: str) -> str:
        if not isinstance(data, str) or not data.startswith("ENC:") or not hasattr(self, 'encryption_key_bytes'):
            return data
        try:
            import base64
            raw = base64.b64decode(data[4:])
            iv, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
            cipher = Cipher(
                algorithms.AES(self.encryption_key_bytes),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            print(f"[security] Decryption failed: {e}")
            return data

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    privkey_store TEXT NOT NULL,
                    pake_password TEXT NOT NULL,
                    meta TEXT,
                    version INT NOT NULL,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    creator_id TEXT NOT NULL,
                    created_at INT,
                    meta TEXT,
                    version INT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    role TEXT,
                    wrapped_key TEXT NOT NULL,
                    added_at INT,
                    PRIMARY KEY (group_id, member_id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS message_queue (
                    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    wrapped_key TEXT NOT NULL,
                    sender_pub TEXT,
                    content_sig TEXT,
                    queued_at INTEGER DEFAULT (strftime('%s','now')),
                    expires_at INTEGER,
                    delivered INTEGER DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER DEFAULT (strftime('%s','now')),
                    event_type TEXT NOT NULL,
                    entity_id TEXT,
                    details TEXT,
                    severity TEXT DEFAULT 'INFO'
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_group_members_gid ON group_members(group_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_message_queue_recipient ON message_queue(recipient_id, delivered)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_message_queue_expires ON message_queue(expires_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit(timestamp)')
            cursor.execute("""
                INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                VALUES ('public','system', strftime('%s','now'), '{}', 1)
                ON CONFLICT(group_id) DO NOTHING
            """)
            conn.commit()
        self._set_secure_permissions()

    def _validate_user_id(self, user_id: str) -> bool:
        if not isinstance(user_id, str) or len(user_id) < 1 or len(user_id) > 255:
            return False
        import re
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', user_id))

    def _validate_message_ids(self, message_ids: List[Any]) -> List[int]:
        validated = []
        for mid in message_ids:
            try:
                mid_int = int(mid)
                if mid_int > 0:
                    validated.append(mid_int)
            except (ValueError, TypeError):
                self._audit_log_direct("INVALID_INPUT", None, f"Invalid message_id rejected: {repr(mid)}", "WARNING")
        if len(validated) > self.MAX_MESSAGE_ID_BATCH:
            self._audit_log_direct("RATE_LIMIT", None, f"Message ID batch truncated: {len(validated)} -> {self.MAX_MESSAGE_ID_BATCH}", "WARNING")
            validated = validated[:self.MAX_MESSAGE_ID_BATCH]
        return validated

    def _audit_log_direct(self, event_type: str, entity_id: Optional[str], details: str, severity: str = "INFO"):
        try:
            with self._get_conn() as conn:
                conn.execute('''
                    INSERT INTO security_audit (event_type, entity_id, details, severity)
                    VALUES (?, ?, ?, ?)
                ''', (event_type, entity_id, details, severity))
        except Exception as e:
            print(f"[audit] Failed to log event: {e}")

    def _audit_log(self, conn, event_type: str, entity_id: Optional[str], details: str, severity: str = "INFO"):
        try:
            conn.execute('''
                INSERT INTO security_audit (event_type, entity_id, details, severity)
                VALUES (?, ?, ?, ?)
            ''', (event_type, entity_id, details, severity))
        except Exception as e:
            print(f"[audit] Failed to log event: {e}")

    def add_or_update_user(self, user_id: str, pubkey_b64u: str, server_id: str,
                           metadata: Optional[Dict] = None,
                           privkey_store: Optional[str] = None,
                           pake_password: Optional[str] = None) -> bool:
        if not self._validate_user_id(user_id):
            self._audit_log_direct("INVALID_INPUT", user_id, "Invalid user_id format", "WARNING")
            return False
        if not isinstance(pubkey_b64u, str) or len(pubkey_b64u) > 10000:
            self._audit_log_direct("INVALID_INPUT", user_id, "Invalid pubkey format", "WARNING")
            return False
        try:
            with self._get_conn() as conn:
                meta_json = json.dumps(metadata or {})
                pstore = privkey_store or ""
                pver = pake_password or ""

                if hasattr(self, "encryption_key_bytes"):
                    if pstore:
                        pstore = self._encrypt_data(pstore)
                    if pver:
                        pver = self._encrypt_data(pver)

                conn.execute('''
                    INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(user_id) DO UPDATE SET
                        pubkey = excluded.pubkey,
                        meta = excluded.meta,
                        privkey_store = CASE WHEN excluded.privkey_store <> '' THEN excluded.privkey_store ELSE privkey_store END,
                        pake_password = CASE WHEN excluded.pake_password <> '' THEN excluded.pake_password ELSE pake_password END
                ''', (user_id, pubkey_b64u, pstore, pver, meta_json))

                self._audit_log(conn, "USER_REGISTER", user_id, "User registered/updated", "INFO")
                return True
        except sqlite3.Error as e:
            self._audit_log_direct("DB_ERROR", user_id, f"Error adding user: {e}", "ERROR")
            print(f"[db] Error adding user: {e}")
            return False

    def update_user_status(self, user_id: str, is_online: bool, server_id: Optional[str] = None):
        return

    def get_user_pubkey(self, user_id: str) -> Optional[str]:
        if not self._validate_user_id(user_id):
            return None
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT pubkey FROM users
                WHERE user_id = ?
                   OR json_extract(meta, '$.name') = ?
                ORDER BY CASE WHEN user_id = ? THEN 0 ELSE 1 END
                LIMIT 1
                """,
                (user_id, user_id, user_id),
            )
            row = cursor.fetchone()
            return row['pubkey'] if row else None

    def get_user_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        if not isinstance(name, str) or len(name) > 255:
            return None
        with self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    SELECT user_id, pubkey, privkey_store, pake_password, meta, version
                    FROM users
                    WHERE json_extract(meta, '$.name') = ?
                    LIMIT 1
                    """,
                    (name,),
                )
            except sqlite3.Error:
                return None
            row = cursor.fetchone()
            if not row:
                return None
            out = dict(row)
            for k in ("privkey_store", "pake_password"):
                if isinstance(out.get(k), str) and out[k].startswith("ENC:"):
                    out[k] = self._decrypt_data(out[k])
            return out

    def get_user_by_uuid(self, user_uuid: str) -> Optional[Dict[str, Any]]:
        if not self._validate_user_id(user_uuid):
            return None
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT user_id, pubkey, privkey_store, pake_password, meta, version FROM users WHERE user_id = ? LIMIT 1',
                (user_uuid,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            out = dict(row)
            for k in ("privkey_store", "pake_password"):
                if isinstance(out.get(k), str) and out[k].startswith("ENC:"):
                    out[k] = self._decrypt_data(out[k])
            return out

    def get_user_location(self, user_id: str) -> Optional[str]:
        return None

    def get_user_locations_dict(self) -> Dict[str, str]:
        return {}

    def get_user_pubkeys_dict(self) -> Dict[str, str]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT user_id, pubkey FROM users')
            return {row['user_id']: row['pubkey'] for row in cursor.fetchall()}

    def add_or_update_server(self, server_id: str, host: str, port: int,
                             pubkey_b64u: Optional[str] = None, is_connected: bool = False):
        return

    def update_server_connection_status(self, server_id: str, is_connected: bool):
        return

    def get_server_addrs_dict(self) -> Dict[str, Tuple[str, int]]:
        return {}

    def get_server_pubkeys_list(self) -> List[Tuple[str, str]]:
        return []

    def queue_message(self, recipient_id: str, sender_id: str, ciphertext: str,
                      iv: str, tag: str, wrapped_key: str,
                      sender_pub: Optional[str] = None, content_sig: Optional[str] = None):
        if not self._validate_user_id(recipient_id) or not self._validate_user_id(sender_id):
            self._audit_log_direct("INVALID_INPUT", recipient_id, "Invalid user_id in queue_message", "WARNING")
            return
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) as count FROM message_queue WHERE recipient_id = ? AND delivered = 0',
                (recipient_id,)
            )
            count = cursor.fetchone()['count']
            if count >= self.MAX_QUEUED_MESSAGES_PER_USER:
                self._audit_log(conn, "QUEUE_LIMIT", recipient_id, f"Message queue full ({count} messages)", "WARNING")
                cursor.execute('''
                    DELETE FROM message_queue
                    WHERE message_id IN (
                        SELECT message_id FROM message_queue
                        WHERE recipient_id = ? AND delivered = 0
                        ORDER BY queued_at ASC LIMIT 1
                    )
                ''', (recipient_id,))
            import time
            expires_at = int(time.time()) + (self.MESSAGE_EXPIRY_DAYS * 86400)
            conn.execute('''
                INSERT INTO message_queue
                (recipient_id, sender_id, ciphertext, iv, tag, wrapped_key, sender_pub, content_sig, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (recipient_id, sender_id, ciphertext, iv, tag, wrapped_key, sender_pub, content_sig, expires_at))

    def get_queued_messages(self, recipient_id: str) -> List[Dict[str, Any]]:
        if not self._validate_user_id(recipient_id):
            return []
        with self._get_conn() as conn:
            cursor = conn.cursor()
            import time
            current_time = int(time.time())
            cursor.execute('''
                SELECT message_id, sender_id, ciphertext, iv, tag, wrapped_key, sender_pub, content_sig, queued_at
                FROM message_queue
                WHERE recipient_id = ? AND delivered = 0 AND expires_at > ?
                ORDER BY queued_at ASC
            ''', (recipient_id, current_time))
            return [dict(row) for row in cursor.fetchall()]

    def mark_messages_delivered(self, message_ids: List[int]):
        if not message_ids:
            return
        validated_ids = self._validate_message_ids(message_ids)
        if not validated_ids:
            self._audit_log_direct("INVALID_INPUT", None, "No valid message IDs in mark_messages_delivered", "WARNING")
            return
        try:
            with self._get_conn() as conn:
                placeholders = ','.join('?' * len(validated_ids))
                query = f'UPDATE message_queue SET delivered = 1 WHERE message_id IN ({placeholders})'
                conn.execute(query, validated_ids)
                self._audit_log(conn, "MESSAGES_DELIVERED", None, f"Marked {len(validated_ids)} messages as delivered", "INFO")
        except sqlite3.Error as e:
            self._audit_log_direct("DB_ERROR", None, f"Error marking messages delivered: {e}", "ERROR")
            print(f"[db] Error marking messages delivered: {e}")

    def _cleanup_expired_messages(self):
        try:
            with self._get_conn() as conn:
                import time
                current_time = int(time.time())
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM message_queue
                    WHERE expires_at < ? OR (delivered = 1 AND queued_at < ?)
                ''', (current_time, current_time - (self.MESSAGE_EXPIRY_DAYS * 86400)))
                deleted = cursor.rowcount
                if deleted > 0:
                    self._audit_log(conn, "CLEANUP", None, f"Cleaned up {deleted} expired messages", "INFO")
        except Exception as e:
            print(f"[db] Error cleaning up messages: {e}")

    def get_stats(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as total FROM users')
            total_users = cursor.fetchone()['total']
            online_users = 0
            total_servers = 0
            cursor.execute('SELECT COUNT(*) as count FROM message_queue WHERE delivered = 0')
            queued_messages = cursor.fetchone()['count']
            cursor.execute('SELECT COUNT(*) as groups_total FROM groups')
            groups_total = cursor.fetchone()['groups_total']
            return {
                "total_users": total_users,
                "online_users": online_users,
                "total_servers": total_servers,
                "queued_messages": queued_messages,
                "groups": groups_total,
            }

    def get_audit_logs(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if severity:
                cursor.execute('''
                    SELECT audit_id, timestamp, event_type, entity_id, details, severity
                    FROM security_audit
                    WHERE severity = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (severity, limit))
            else:
                cursor.execute('''
                    SELECT audit_id, timestamp, event_type, entity_id, details, severity
                    FROM security_audit
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def upsert_group(self, group_id: str, creator_id: str = 'system',
                     meta: Optional[Dict] = None, version: int = 1):
        if not self._validate_user_id(group_id) or not self._validate_user_id(creator_id):
            return
        with self._get_conn() as conn:
            m = json.dumps(meta or {})
            conn.execute('''
                INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                VALUES (?, ?, strftime('%s','now'), ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET meta=excluded.meta, version=excluded.version
            ''', (group_id, creator_id, m, version))

    def upsert_group_member(self, group_id: str, member_id: str, wrapped_key: str, role: str = 'member'):
        if not self._validate_user_id(group_id) or not self._validate_user_id(member_id):
            return
        with self._get_conn() as conn:
            conn.execute('''
                INSERT INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                VALUES (?, ?, ?, ?, strftime('%s','now'))
                ON CONFLICT(group_id, member_id) DO UPDATE SET role=excluded.role, wrapped_key=excluded.wrapped_key
            ''', (group_id, member_id, role, wrapped_key))

    def list_group_members(self, group_id: str) -> List[Dict[str, Any]]:
        if not self._validate_user_id(group_id):
            return []
        with self._get_conn() as conn:
            cur = conn.execute(
                'SELECT member_id, role, wrapped_key, added_at FROM group_members WHERE group_id = ?',
                (group_id,)
            )
            return [dict(row) for row in cur.fetchall()]
