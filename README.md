# Kanshi

Kanshi es una herramienta de descubrimiento y monitorización ligera de red local orientada a inventario defensivo. Permite detectar hosts activos en una LAN mediante ARP, guardar escaneos, compararlos, mantener histórico en SQLite y visualizarlos desde un dashboard web local.

## Características

- Descubrimiento de hosts activos por ARP
- Resolución opcional de hostname
- Detección opcional de fabricante por MAC
- Exportación a JSON, CSV y HTML
- Snapshots de escaneos
- Comparación de escaneos (diff)
- Modo watch para monitorización periódica
- Persistencia en SQLite
- Dashboard web local con:
  - listado de escaneos
  - comparación entre escaneos
  - inventario histórico de hosts
  - vista por MAC e IP
- Eliminación de escaneos desde CLI y dashboard

## Estructura del proyecto

```text
kanshi/
├── kanshi.py
├── kanshi_dashboard.py
├── requirements.txt
├── README.md
├── .gitignore
└── docs/
    └── screenshots/
```

## Requisitos

- Python 3.10 o superior
- Linux recomendado
- Privilegios elevados para el escaneo ARP
- Npcap en Windows si se usa Scapy allí

## Instalación

Clona el repositorio y crea un entorno virtual:

```bash
git clone https://github.com/TU_USUARIO/kanshi.git
cd kanshi
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Dependencias

Ejemplo de `requirements.txt`:

```txt
scapy
psutil
rich
flask
manuf
```

## Uso básico

Escaneo simple:

```bash
sudo .venv/bin/python kanshi.py
```

Escaneo con hostname y fabricante:

```bash
sudo .venv/bin/python kanshi.py --resolve-names --vendor
```

Guardar en SQLite:

```bash
sudo .venv/bin/python kanshi.py --db-save --label casa
```

Guardar snapshot:

```bash
sudo .venv/bin/python kanshi.py --snapshot --label casa
```

Comparar con el último snapshot:

```bash
sudo .venv/bin/python kanshi.py --compare-last
```

Modo watch:

```bash
sudo .venv/bin/python kanshi.py --watch --interval 30
```

Modo watch mostrando solo cambios:

```bash
sudo .venv/bin/python kanshi.py --watch --interval 30 --watch-changes-only
```

Modo watch guardando snapshot solo si hay cambios:

```bash
sudo .venv/bin/python kanshi.py --watch --interval 30 --watch-changes-only --save-on-change --beep
```

Exportar resultados:

```bash
sudo .venv/bin/python kanshi.py --json-out scan.json --csv-out scan.csv --html-out report.html
```

## SQLite

Guardar un escaneo en la base de datos:

```bash
sudo .venv/bin/python kanshi.py --db-save --label casa
```

Listar escaneos guardados:

```bash
python kanshi.py --db-list
```

Comparar dos escaneos de SQLite:

```bash
python kanshi.py --db-diff 3 8
```

Eliminar escaneos desde CLI:

```bash
python kanshi.py --db-remove 12 13 14
```

Eliminar sin confirmación interactiva:

```bash
python kanshi.py --db-remove 12 13 14 --yes
```

## Dashboard web

Lanzar el dashboard:

```bash
python kanshi_dashboard.py --db-path kanshi.db
```

Abrir en navegador:

```text
http://127.0.0.1:5000
```

### Funcionalidades del dashboard

- Vista general de escaneos
- Filtros por label
- Búsqueda por IP, MAC, hostname, vendor y role
- Descarga de JSON y CSV por escaneo
- Comparación de escaneos desde la web
- Evolución de hosts por escaneo
- Inventario histórico de dispositivos
- Vista histórica por MAC
- Vista histórica por IP
- Eliminación de escaneos desde la interfaz web

## Flujo de trabajo recomendado

1. Ejecutar escaneos y guardarlos en SQLite:

```bash
sudo .venv/bin/python kanshi.py --resolve-names --vendor --db-save --label casa
```

2. Levantar el dashboard:

```bash
python kanshi_dashboard.py --db-path kanshi.db
```

3. Consultar en el navegador:
   - escaneos históricos
   - cambios entre scans
   - hosts persistentes vistos a lo largo del tiempo

## Permisos y base de datos

El dashboard debe ejecutarse sin `sudo`.

Como el escaneo ARP sí puede requerir privilegios elevados, conviene vigilar los permisos de `kanshi.db` para evitar errores de escritura en SQLite.

Comprobar permisos:

```bash
ls -l kanshi.db*
```

Corregir propietario si fuese necesario:

```bash
sudo chown "$USER":"$USER" kanshi.db*
```

## Casos de uso

Kanshi está orientado a:

- inventario ligero de red local
- trazabilidad de dispositivos en una LAN
- monitorización básica de cambios de presencia
- análisis histórico de apariciones por MAC o IP
- portfolio técnico en ciberseguridad defensiva y asset discovery

## Aviso legal y ético

Kanshi debe utilizarse únicamente en redes propias o donde exista autorización expresa. Su finalidad es defensiva, de inventario y monitorización ligera en entornos controlados.

## Roadmap

Líneas futuras de evolución:

- reglas y alertas
- dashboard con más analítica
- exportes más avanzados
- clasificación de dispositivos
- mejoras visuales y de reporting

## Licencia

Pendiente de definir.

