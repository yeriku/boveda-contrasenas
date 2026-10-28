"""
Bóveda de Contraseñas - interfaz gráfica (Tkinter).
Ejecutar:  python boveda_gui.py
"""

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from boveda_core import (DEMO_CREDENTIALS, MasterPasswordError, Vault,
                         VaultNotInitialized)

DB_PATH = "boveda.db"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Bóveda de Contraseñas - CIB-06")
        self.geometry("760x480")
        self.vault = Vault(DB_PATH)
        self.master_pwd = None  # solo en memoria mientras la sesión está abierta
        self._build()
        self.after(100, self._login)

    # ---------- interfaz ----------
    def _build(self):
        top = ttk.LabelFrame(self, text="1. Contraseña maestra")
        top.pack(fill="x", padx=10, pady=6)
        self.lbl_estado = ttk.Label(top, text="Bóveda bloqueada")
        self.lbl_estado.pack(side="left", padx=8, pady=6)
        ttk.Button(top, text="Ingresar / cambiar sesión", command=self._login).pack(side="right", padx=8)

        form = ttk.LabelFrame(self, text="2. Registrar credencial")
        form.pack(fill="x", padx=10, pady=6)
        self.var_serv, self.var_user, self.var_pass = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for col, (txt, var, show) in enumerate([("Servicio", self.var_serv, ""),
                                                ("Usuario", self.var_user, ""),
                                                ("Contraseña", self.var_pass, "*")]):
            ttk.Label(form, text=txt).grid(row=0, column=col, padx=6, sticky="w")
            ttk.Entry(form, textvariable=var, show=show, width=22).grid(row=1, column=col, padx=6, pady=4)
        ttk.Button(form, text="Guardar cifrada", command=self._add).grid(row=1, column=3, padx=8)
        ttk.Button(form, text="Cargar 5 de demo", command=self._demo).grid(row=1, column=4, padx=4)

        lst = ttk.LabelFrame(self, text="3. Credenciales guardadas")
        lst.pack(fill="both", expand=True, padx=10, pady=6)
        cols = ("id", "servicio", "usuario", "password")
        self.tree = ttk.Treeview(lst, columns=cols, show="headings", height=9)
        for c, w in zip(cols, (40, 260, 200, 120)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)
        btns = ttk.Frame(lst)
        btns.pack(fill="x", padx=6, pady=4)
        ttk.Button(btns, text="Ver contraseña seleccionada", command=self._reveal).pack(side="left")
        ttk.Button(btns, text="Eliminar", command=self._delete).pack(side="left", padx=6)
        self._refresh()

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        for i, s, u, _ in self.vault.list_entries():
            self.tree.insert("", "end", values=(i, s, u, "********"))

    # ---------- acciones ----------
    def _login(self):
        try:
            if not self.vault.is_initialized():
                m1 = simpledialog.askstring("Definir contraseña maestra",
                                            "Defina la contraseña maestra (mín. 8 caracteres):",
                                            show="*", parent=self)
                if not m1:
                    return
                m2 = simpledialog.askstring("Confirmar", "Repita la contraseña maestra:",
                                            show="*", parent=self)
                if m1 != m2:
                    messagebox.showerror("Error", "Las contraseñas no coinciden.")
                    return
                self.vault.initialize(m1)
                self.master_pwd = m1
            else:
                m = simpledialog.askstring("Contraseña maestra", "Ingrese la contraseña maestra:",
                                           show="*", parent=self)
                if not m:
                    return
                if not self.vault.check_master(m):
                    self.master_pwd = None
                    self.lbl_estado.config(text="Bóveda bloqueada")
                    messagebox.showerror("Acceso denegado", "Contraseña maestra incorrecta.")
                    return
                self.master_pwd = m
            self.lbl_estado.config(text="Bóveda desbloqueada")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def _need_master(self):
        if self.master_pwd is None:
            messagebox.showwarning("Bloqueada", "Ingrese primero la contraseña maestra.")
            return False
        return True

    def _add(self):
        if not self._need_master():
            return
        try:
            i = self.vault.add(self.master_pwd, self.var_serv.get(), self.var_user.get(), self.var_pass.get())
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        self.var_serv.set(""); self.var_user.set(""); self.var_pass.set("")
        self._refresh()
        messagebox.showinfo("Guardado", f"Registro #{i} almacenado cifrado.")

    def _demo(self):
        if not self._need_master():
            return
        for s, u, p in DEMO_CREDENTIALS:
            self.vault.add(self.master_pwd, s, u, p)
        self._refresh()

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Seleccione", "Seleccione una entrada de la lista.")
            return None
        return int(self.tree.item(sel[0])["values"][0])

    def _reveal(self):
        eid = self._selected_id()
        if eid is None:
            return
        # Se vuelve a pedir la maestra: así la prueba de "maestra incorrecta" es demostrable.
        m = simpledialog.askstring("Descifrar", "Ingrese la contraseña maestra:", show="*", parent=self)
        if not m:
            return
        try:
            pwd = self.vault.reveal(m, eid)
        except MasterPasswordError:
            messagebox.showerror("No se puede descifrar", "Contraseña maestra incorrecta.\nEl secreto no fue recuperado.")
            return
        messagebox.showinfo("Contraseña descifrada", f"Contraseña: {pwd}")

    def _delete(self):
        eid = self._selected_id()
        if eid is None or not self._need_master():
            return
        if messagebox.askyesno("Eliminar", f"¿Eliminar la entrada #{eid}?"):
            self.vault.delete(self.master_pwd, eid)
            self._refresh()


if __name__ == "__main__":
    App().mainloop()
