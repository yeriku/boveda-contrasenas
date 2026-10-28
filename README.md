# Bóveda de Contraseñas (CIB-06, Actividad Clase 04)

Aplicación que guarda credenciales ficticias con la contraseña **cifrada** (AES-256-GCM) en SQLite. La clave sale de una **contraseña maestra** mediante scrypt; la maestra y la clave nunca se almacenan.

## Requisitos
- Python 3.10 o superior (Windows o Linux)
- Librería `cryptography`

```
pip install -r requirements.txt
```
Interfaz gráfica: usa Tkinter (viene con Python en Windows; en Linux: `sudo apt install python3-tk`).

## Ejecución

Interfaz gráfica:
```
python boveda_gui.py
```
La primera vez pide definir la contraseña maestra. Luego: registrar credencial, "Cargar 5 de demo", seleccionar una fila y "Ver contraseña seleccionada" (pide la maestra).

Línea de comandos (útil para la evidencia):
```
python boveda_cli.py init
python boveda_cli.py demo                 # guarda 5 credenciales ficticias
python boveda_cli.py list                 # sin contraseñas
python boveda_cli.py show 1               # descifra con la maestra
python boveda_cli.py inspect --buscar "Demo#Correo2026"   # lo que hay realmente en la BD
```

## Pruebas
```
python -m unittest -v test_boveda
```
Cubren las 5 pruebas obligatorias (guardado, inspección, descifrado correcto, maestra incorrecta, persistencia) y casos extra (nonce único, detección de alteración).

## Dónde están los datos
Archivo `boveda.db` (SQLite) junto al código. Se puede abrir con "DB Browser for SQLite" o con `sqlite3 boveda.db "select * from credenciales;"`. Para volver a crearla basta borrar el archivo y ejecutar de nuevo.

## Qué se guarda
| Tabla | Campos |
|---|---|
| `meta` | salt (16 B), parámetros de scrypt, verificador HMAC de la maestra |
| `credenciales` | servicio, usuario (texto plano), nonce (12 B), password_cifrada (AES-GCM + tag) |

Solo se usan credenciales ficticias.
