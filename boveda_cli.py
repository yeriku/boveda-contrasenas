"""
Bóveda de Contraseñas - interfaz de línea de comandos.

Uso:
  python boveda_cli.py init              Define la contraseña maestra
  python boveda_cli.py add               Registra una credencial
  python boveda_cli.py list              Lista las entradas (sin contraseñas)
  python boveda_cli.py show ID           Descifra la contraseña de una entrada
  python boveda_cli.py demo              Carga 5 credenciales ficticias
  python boveda_cli.py inspect           Muestra lo que hay realmente en la BD

Opción global: --db RUTA   (por defecto boveda.db)
Para pruebas automatizadas se acepta la variable de entorno BOVEDA_MASTER;
en uso normal la contraseña maestra se pide de forma oculta.
"""

import argparse
import getpass
import os
import sys

from boveda_core import (DEMO_CREDENTIALS, MasterPasswordError, Vault,
                         VaultAlreadyInitialized, VaultNotInitialized)


def ask_master(prompt="Contraseña maestra: "):
    env = os.environ.get("BOVEDA_MASTER")
    return env if env is not None else getpass.getpass(prompt)


def cmd_init(v, a):
    m1 = ask_master("Defina la contraseña maestra: ")
    if os.environ.get("BOVEDA_MASTER") is None:
        if m1 != getpass.getpass("Repita la contraseña maestra: "):
            print("Las contraseñas no coinciden.")
            return 1
    v.initialize(m1)
    print("Bóveda inicializada. La contraseña maestra NO se guardó; solo un verificador.")
    return 0


def cmd_add(v, a):
    master = ask_master()
    servicio = a.servicio or input("Servicio o sitio: ")
    usuario = a.usuario or input("Usuario: ")
    pwd = a.password or getpass.getpass("Contraseña a guardar: ")
    i = v.add(master, servicio, usuario, pwd)
    print(f"Registro #{i} almacenado (contraseña cifrada).")
    return 0


def cmd_list(v, a):
    rows = v.list_entries()
    if not rows:
        print("(la bóveda no tiene entradas)")
        return 0
    print(f"{'ID':<4} {'SERVICIO':<28} {'USUARIO':<20} CONTRASEÑA")
    for i, s, u, _ in rows:
        print(f"{i:<4} {s:<28} {u:<20} ********")
    return 0


def cmd_show(v, a):
    master = ask_master()
    try:
        print(v.reveal(master, a.id))
    except MasterPasswordError:
        print("ERROR: contraseña maestra incorrecta. No se puede descifrar.")
        return 2
    except KeyError as e:
        print(f"ERROR: {e}")
        return 3
    return 0


def cmd_demo(v, a):
    master = ask_master()
    if not v.is_initialized():
        v.initialize(master)
    for s, u, p in DEMO_CREDENTIALS:
        i = v.add(master, s, u, p)
        print(f"#{i} {s} / {u}  -> guardada cifrada")
    return 0


def cmd_inspect(v, a):
    """Muestra el contenido crudo de la BD, como lo vería un atacante con el archivo."""
    print(f"Archivo: {v.db_path}")
    print("-" * 78)
    for i, s, u, nonce, ct in v.raw_rows():
        print(f"id={i}  servicio={s}  usuario={u}")
        print(f"   nonce (hex)          = {nonce}")
        print(f"   password_cifrada(hex)= {ct}")
    if a.buscar:
        with open(v.db_path, "rb") as f:
            data = f.read()
        print("-" * 78)
        for pwd in a.buscar:
            found = pwd.encode("utf-8") in data
            print(f"¿'{pwd}' aparece en texto plano en el archivo?  {'SÍ' if found else 'NO'}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Bóveda de Contraseñas (CLI)")
    p.add_argument("--db", default="boveda.db")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    pa = sub.add_parser("add")
    pa.add_argument("--servicio")
    pa.add_argument("--usuario")
    pa.add_argument("--password", help="solo para pruebas; si se omite se pide oculta")
    sub.add_parser("list")
    ps = sub.add_parser("show")
    ps.add_argument("id", type=int)
    sub.add_parser("demo")
    pi = sub.add_parser("inspect")
    pi.add_argument("--buscar", nargs="*", help="textos a buscar en el archivo de la BD")
    a = p.parse_args()

    v = Vault(a.db)
    fn = {"init": cmd_init, "add": cmd_add, "list": cmd_list, "show": cmd_show,
          "demo": cmd_demo, "inspect": cmd_inspect}[a.cmd]
    try:
        return fn(v, a)
    except VaultNotInitialized as e:
        print(f"ERROR: {e} Ejecute 'init'.")
        return 4
    except VaultAlreadyInitialized as e:
        print(f"ERROR: {e}")
        return 5
    except MasterPasswordError:
        print("ERROR: contraseña maestra incorrecta.")
        return 2
    except ValueError as e:
        print(f"ERROR: {e}")
        return 6


if __name__ == "__main__":
    sys.exit(main())
