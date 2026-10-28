"""
Bóveda de Contraseñas - núcleo criptográfico y de almacenamiento.
CIB-06 Criptografía II: Aplicaciones - UISIL

Diseño:
  - Derivación de clave: scrypt (contraseña maestra + salt aleatorio de 16 bytes)
    produce 64 bytes:  [0:32]  -> clave AES-256   (nunca se guarda)
                       [32:64] -> clave para verificar la contraseña maestra
  - Cifrado de cada contraseña: AES-256-GCM (cifrado autenticado), con un
    nonce aleatorio de 12 bytes distinto por registro.
  - Datos asociados (AAD): servicio y usuario del registro, para que no se
    pueda copiar un cifrado de una fila a otra sin que falle la autenticación.
  - Fuente de datos: SQLite (archivo boveda.db).
  - Lo que se guarda: salt, parámetros de scrypt, verificador (HMAC) y, por
    registro, servicio, usuario (texto plano), nonce y texto cifrado.
  - NO se guarda: contraseña maestra, clave AES, ni contraseñas en claro.
"""

import hashlib
import hmac
import os
import sqlite3
from contextlib import closing

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRYPT_N = 2 ** 15   # costo de CPU/memoria (~32 MiB)
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 16
NONCE_LEN = 12
MIN_MASTER_LEN = 8
VERIFIER_LABEL = b"boveda-verificacion-v1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    salt        BLOB    NOT NULL,
    scrypt_n    INTEGER NOT NULL,
    scrypt_r    INTEGER NOT NULL,
    scrypt_p    INTEGER NOT NULL,
    verificador BLOB    NOT NULL
);
CREATE TABLE IF NOT EXISTS credenciales (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    servicio         TEXT NOT NULL,
    usuario          TEXT NOT NULL,
    nonce            BLOB NOT NULL,
    password_cifrada BLOB NOT NULL,
    creado           TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class MasterPasswordError(Exception):
    """La contraseña maestra es incorrecta."""


class VaultNotInitialized(Exception):
    """La bóveda todavía no tiene contraseña maestra definida."""


class VaultAlreadyInitialized(Exception):
    """La bóveda ya tiene una contraseña maestra."""


def _derive(master: str, salt: bytes, n: int, r: int, p: int):
    material = hashlib.scrypt(
        master.encode("utf-8"), salt=salt, n=n, r=r, p=p,
        maxmem=128 * 1024 * 1024, dklen=64,
    )
    return material[:32], material[32:]


def _verifier(verif_key: bytes) -> bytes:
    return hmac.new(verif_key, VERIFIER_LABEL, hashlib.sha256).digest()


def _aad(servicio: str, usuario: str) -> bytes:
    return f"{servicio}\x00{usuario}".encode("utf-8")


class Vault:
    def __init__(self, db_path: str = "boveda.db"):
        self.db_path = db_path
        with closing(self._conn()) as c:
            c.executescript(SCHEMA)

    def _conn(self):
        return sqlite3.connect(self.db_path)

    # ---------- estado ----------
    def is_initialized(self) -> bool:
        with closing(self._conn()) as c:
            return c.execute("SELECT 1 FROM meta WHERE id = 1").fetchone() is not None

    def initialize(self, master: str) -> None:
        """Define la contraseña maestra por primera vez."""
        if self.is_initialized():
            raise VaultAlreadyInitialized("La bóveda ya fue inicializada.")
        if len(master) < MIN_MASTER_LEN:
            raise ValueError(
                f"La contraseña maestra debe tener al menos {MIN_MASTER_LEN} caracteres.")
        salt = os.urandom(SALT_LEN)
        _, verif_key = _derive(master, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        with closing(self._conn()) as c, c:
            c.execute(
                "INSERT INTO meta (id, salt, scrypt_n, scrypt_r, scrypt_p, verificador)"
                " VALUES (1, ?, ?, ?, ?, ?)",
                (salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, _verifier(verif_key)),
            )

    def _unlock(self, master: str) -> bytes:
        """Devuelve la clave AES si la maestra es correcta; si no, lanza error."""
        with closing(self._conn()) as c:
            row = c.execute(
                "SELECT salt, scrypt_n, scrypt_r, scrypt_p, verificador FROM meta WHERE id = 1"
            ).fetchone()
        if row is None:
            raise VaultNotInitialized("Primero debe definir la contraseña maestra.")
        salt, n, r, p, stored = row
        enc_key, verif_key = _derive(master, salt, n, r, p)
        if not hmac.compare_digest(_verifier(verif_key), stored):
            raise MasterPasswordError("Contraseña maestra incorrecta.")
        return enc_key

    def check_master(self, master: str) -> bool:
        try:
            self._unlock(master)
            return True
        except MasterPasswordError:
            return False

    # ---------- operaciones ----------
    def add(self, master: str, servicio: str, usuario: str, password: str) -> int:
        servicio, usuario = servicio.strip(), usuario.strip()
        if not servicio or not usuario or not password:
            raise ValueError("Servicio, usuario y contraseña son obligatorios.")
        key = self._unlock(master)
        nonce = os.urandom(NONCE_LEN)
        cifrada = AESGCM(key).encrypt(nonce, password.encode("utf-8"), _aad(servicio, usuario))
        with closing(self._conn()) as c, c:
            cur = c.execute(
                "INSERT INTO credenciales (servicio, usuario, nonce, password_cifrada)"
                " VALUES (?, ?, ?, ?)",
                (servicio, usuario, nonce, cifrada),
            )
            return cur.lastrowid

    def list_entries(self):
        """Lista sin descifrar: (id, servicio, usuario, creado)."""
        with closing(self._conn()) as c:
            return c.execute(
                "SELECT id, servicio, usuario, creado FROM credenciales ORDER BY id"
            ).fetchall()

    def reveal(self, master: str, entry_id: int) -> str:
        """Descifra la contraseña de una entrada. Falla si la maestra es incorrecta."""
        key = self._unlock(master)
        with closing(self._conn()) as c:
            row = c.execute(
                "SELECT servicio, usuario, nonce, password_cifrada FROM credenciales WHERE id = ?",
                (entry_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"No existe la entrada {entry_id}.")
        servicio, usuario, nonce, cifrada = row
        try:
            return AESGCM(key).decrypt(nonce, cifrada, _aad(servicio, usuario)).decode("utf-8")
        except InvalidTag:
            raise ValueError("El registro está alterado o no se pudo autenticar.")

    def delete(self, master: str, entry_id: int) -> None:
        self._unlock(master)
        with closing(self._conn()) as c, c:
            c.execute("DELETE FROM credenciales WHERE id = ?", (entry_id,))

    def raw_rows(self):
        """Filas tal como están en disco (para inspección/evidencia)."""
        with closing(self._conn()) as c:
            return c.execute(
                "SELECT id, servicio, usuario, hex(nonce), hex(password_cifrada) "
                "FROM credenciales ORDER BY id"
            ).fetchall()


# Credenciales ficticias para la demostración
DEMO_CREDENTIALS = [
    ("Correo de prueba", "usuario.demo", "Demo#Correo2026"),
    ("Red social demo", "ana.ficticia", "Soc1al!Falsa99"),
    ("Banco de prueba", "cliente.demo01", "Banc0*Ficticio7"),
    ("Servidor de laboratorio", "admin.lab", "Lab$Server_42"),
    ("Plataforma de cursos", "estudiante.demo", "Cursos+Test2026"),
]
