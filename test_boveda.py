"""Pruebas obligatorias de la actividad (ejecutar: python -m unittest -v test_boveda)."""
import os
import tempfile
import unittest

from boveda_core import (DEMO_CREDENTIALS, MasterPasswordError, Vault,
                         VaultAlreadyInitialized)

MASTER = "Maestra#Segura2026"


class TestBoveda(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "boveda.db")
        self.v = Vault(self.db)
        self.v.initialize(MASTER)
        for s, u, p in DEMO_CREDENTIALS:
            self.v.add(MASTER, s, u, p)

    def test_1_guardado(self):
        self.assertEqual(len(self.v.list_entries()), 5)

    def test_2_inspeccion_no_hay_texto_plano(self):
        with open(self.db, "rb") as f:
            data = f.read()
        for _, _, p in DEMO_CREDENTIALS:
            self.assertNotIn(p.encode(), data)
        self.assertNotIn(MASTER.encode(), data)  # la maestra tampoco

    def test_3_descifrado_correcto(self):
        for i, (_, _, p) in enumerate(DEMO_CREDENTIALS, start=1):
            self.assertEqual(self.v.reveal(MASTER, i), p)

    def test_4_maestra_incorrecta(self):
        with self.assertRaises(MasterPasswordError):
            self.v.reveal("otra-clave-123", 1)
        with self.assertRaises(MasterPasswordError):
            self.v.add("otra-clave-123", "x", "y", "z")

    def test_5_persistencia(self):
        v2 = Vault(self.db)  # "reabrir la aplicación"
        self.assertTrue(v2.is_initialized())
        self.assertEqual(len(v2.list_entries()), 5)
        self.assertEqual(v2.reveal(MASTER, 2), DEMO_CREDENTIALS[1][2])

    def test_nonce_distinto_por_registro(self):
        v = Vault(os.path.join(self.tmp, "otra.db"))
        v.initialize(MASTER)
        v.add(MASTER, "a", "u", "misma-clave-1")
        v.add(MASTER, "a", "u", "misma-clave-1")
        rows = v.raw_rows()
        self.assertNotEqual(rows[0][3], rows[1][3])  # nonce
        self.assertNotEqual(rows[0][4], rows[1][4])  # texto cifrado

    def test_alteracion_detectada(self):
        import sqlite3
        c = sqlite3.connect(self.db)
        c.execute("UPDATE credenciales SET usuario='intruso' WHERE id=1")
        c.commit(); c.close()
        with self.assertRaises(ValueError):
            self.v.reveal(MASTER, 1)

    def test_no_reinicializar(self):
        with self.assertRaises(VaultAlreadyInitialized):
            self.v.initialize("otra-maestra-1")

    def test_maestra_corta(self):
        v = Vault(os.path.join(self.tmp, "corta.db"))
        with self.assertRaises(ValueError):
            v.initialize("123")


if __name__ == "__main__":
    unittest.main()
