#!/usr/bin/env python3

import argparse
import csv
import html
import ipaddress
import json
import re
import socket
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psutil
from scapy.all import ARP, Ether, conf, srp  # type: ignore
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    import manuf  # type: ignore
except ImportError:
    manuf = None


console = Console()


def print_banner() -> None:
    banner = r"""
 _  __                _     _
| |/ /__ _ _ __  ___| |__ (_)
| ' // _` | '_ \/ __| '_ \| |
| . \ (_| | | | \__ \ | | | |
|_|\_\__,_|_| |_|___/_| |_|_|

Kanshi v6 - ARP discovery + watch + snapshots + SQLite + HTML
"""
    console.print(Panel.fit(banner.strip(), border_style="cyan"))


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value)
    return value.strip("-") or "scan"


def get_interface_data(interface_name: Optional[str] = None) -> Tuple[str, str, str]:
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    if interface_name:
        if interface_name not in interfaces:
            raise ValueError(f"La interfaz '{interface_name}' no existe.")
        candidates = {interface_name: interfaces[interface_name]}
    else:
        up_interfaces = {
            ifname: addrs
            for ifname, addrs in interfaces.items()
            if ifname in stats and stats[ifname].isup
        }
        candidates = up_interfaces if up_interfaces else interfaces

    for ifname, addrs in candidates.items():
        ipv4_addr = None
        netmask = None

        for addr in addrs:
            if addr.family == socket.AF_INET:
                if addr.address.startswith("127."):
                    continue
                ipv4_addr = addr.address
                netmask = addr.netmask
                break

        if ipv4_addr and netmask:
            return ifname, ipv4_addr, netmask

    raise RuntimeError("No se encontró una interfaz IPv4 válida.")


def calculate_network(ip: str, netmask: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)


def get_default_gateway() -> Optional[str]:
    try:
        gw = conf.route.route("0.0.0.0")[2]
        if not gw or gw == "0.0.0.0":
            return None
        return gw
    except Exception:
        return None


def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "-"


def get_vendor_parser():
    if manuf is None:
        return None
    try:
        return manuf.MacParser()
    except Exception:
        return None


def get_vendor(mac: str, parser) -> str:
    if parser is None:
        return "-"
    try:
        vendor = parser.get_manuf(mac)
        return vendor if vendor else "-"
    except Exception:
        return "-"


def arp_scan(subnet: str, timeout: int = 1) -> List[Dict[str, str]]:
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, verbose=0)

    hosts_by_ip: Dict[str, Dict[str, str]] = {}

    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc.upper()
        hosts_by_ip[ip] = {"ip": ip, "mac": mac}

    return sorted(
        hosts_by_ip.values(),
        key=lambda x: tuple(int(part) for part in x["ip"].split(".")),
    )


def enrich_hosts(
    hosts: List[Dict[str, str]],
    self_ip: str,
    gateway_ip: Optional[str],
    resolve_names: bool,
    vendor_lookup: bool,
    include_self: bool,
) -> List[Dict[str, str]]:
    vendor_parser = get_vendor_parser() if vendor_lookup else None
    enriched = []

    for host in hosts:
        ip = host["ip"]
        mac = host["mac"]

        if ip == self_ip and not include_self:
            continue

        role_parts = []
        if ip == self_ip:
            role_parts.append("SELF")
        if gateway_ip and ip == gateway_ip:
            role_parts.append("GATEWAY")

        enriched.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": resolve_hostname(ip) if resolve_names else "-",
                "vendor": get_vendor(mac, vendor_parser) if vendor_lookup else "-",
                "role": ", ".join(role_parts) if role_parts else "-",
            }
        )

    return enriched


def print_scan_info(interface: str, ip: str, netmask: str, subnet: str, gateway: Optional[str]) -> None:
    table = Table(title="Información del escaneo", show_lines=False)
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("Interfaz", interface)
    table.add_row("IP local", ip)
    table.add_row("Máscara", netmask)
    table.add_row("Subred", subnet)
    table.add_row("Gateway", gateway or "-")

    console.print(table)


def print_results(
    hosts: List[Dict[str, str]],
    show_hostnames: bool = False,
    show_vendor: bool = False,
) -> None:
    if not hosts:
        console.print("[yellow]No se encontraron hosts activos.[/yellow]")
        return

    table = Table(title=f"Hosts detectados ({len(hosts)})", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("MAC", style="magenta", no_wrap=True)

    if show_hostnames:
        table.add_column("HOSTNAME", style="green")
    if show_vendor:
        table.add_column("VENDOR", style="blue")

    table.add_column("ROLE", style="yellow", no_wrap=True)

    for host in hosts:
        row = [host["ip"], host["mac"]]
        if show_hostnames:
            row.append(host["hostname"])
        if show_vendor:
            row.append(host["vendor"])
        row.append(host["role"])
        table.add_row(*row)

    console.print(table)


def build_scan_payload(
    hosts: List[Dict[str, str]],
    interface: str,
    subnet: str,
    self_ip: str,
    gateway_ip: Optional[str],
    label: Optional[str] = None,
) -> Dict:
    return {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "interface": interface,
            "subnet": subnet,
            "self_ip": self_ip,
            "gateway_ip": gateway_ip or "-",
            "host_count": len(hosts),
            "label": label or "-",
        },
        "hosts": hosts,
    }


def export_json_payload(filepath: str, payload: Dict) -> None:
    Path(filepath).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def export_json(
    filepath: str,
    hosts: List[Dict[str, str]],
    interface: str,
    subnet: str,
    self_ip: str,
    gateway_ip: Optional[str],
    label: Optional[str] = None,
) -> None:
    payload = build_scan_payload(
        hosts=hosts,
        interface=interface,
        subnet=subnet,
        self_ip=self_ip,
        gateway_ip=gateway_ip,
        label=label,
    )
    export_json_payload(filepath, payload)


def export_csv(filepath: str, hosts: List[Dict[str, str]]) -> None:
    fieldnames = ["ip", "mac", "hostname", "vendor", "role"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(hosts)


def load_scan_json(filepath: str) -> Dict:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo: {filepath}")

    data = json.loads(path.read_text(encoding="utf-8"))

    if "hosts" not in data:
        raise ValueError(f"El archivo {filepath} no parece un JSON válido de Kanshi.")

    return data


def index_hosts_by_ip(hosts: List[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    return {host["ip"]: host for host in hosts}


def sort_ips(ips: List[str]) -> List[str]:
    return sorted(ips, key=lambda x: tuple(map(int, x.split("."))))


def diff_scans(old_hosts: List[Dict[str, str]], new_hosts: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    old_map = index_hosts_by_ip(old_hosts)
    new_map = index_hosts_by_ip(new_hosts)

    old_ips = set(old_map.keys())
    new_ips = set(new_map.keys())

    added = [new_map[ip] for ip in sort_ips(list(new_ips - old_ips))]
    removed = [old_map[ip] for ip in sort_ips(list(old_ips - new_ips))]
    changed = []

    for ip in sort_ips(list(old_ips & new_ips)):
        old_host = old_map[ip]
        new_host = new_map[ip]

        if old_host.get("mac") != new_host.get("mac"):
            changed.append(
                {
                    "ip": ip,
                    "old_mac": old_host.get("mac", "-"),
                    "new_mac": new_host.get("mac", "-"),
                    "old_hostname": old_host.get("hostname", "-"),
                    "new_hostname": new_host.get("hostname", "-"),
                }
            )

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def diff_has_changes(diff: Dict[str, List[Dict[str, str]]]) -> bool:
    return bool(diff["added"] or diff["removed"] or diff["changed"])


def print_diff(diff: Dict[str, List[Dict[str, str]]]) -> None:
    added = diff["added"]
    removed = diff["removed"]
    changed = diff["changed"]

    summary = Table(title="Resumen del diff")
    summary.add_column("Categoría", style="cyan")
    summary.add_column("Cantidad", style="white")
    summary.add_row("Hosts nuevos", str(len(added)))
    summary.add_row("Hosts desaparecidos", str(len(removed)))
    summary.add_row("Cambios de MAC", str(len(changed)))
    console.print(summary)

    if added:
        table_added = Table(title="Hosts nuevos", border_style="green")
        table_added.add_column("IP", style="cyan")
        table_added.add_column("MAC", style="magenta")
        table_added.add_column("HOSTNAME", style="green")
        table_added.add_column("VENDOR", style="blue")
        table_added.add_column("ROLE", style="yellow")
        for host in added:
            table_added.add_row(
                host.get("ip", "-"),
                host.get("mac", "-"),
                host.get("hostname", "-"),
                host.get("vendor", "-"),
                host.get("role", "-"),
            )
        console.print(table_added)

    if removed:
        table_removed = Table(title="Hosts desaparecidos", border_style="red")
        table_removed.add_column("IP", style="cyan")
        table_removed.add_column("MAC", style="magenta")
        table_removed.add_column("HOSTNAME", style="green")
        table_removed.add_column("VENDOR", style="blue")
        table_removed.add_column("ROLE", style="yellow")
        for host in removed:
            table_removed.add_row(
                host.get("ip", "-"),
                host.get("mac", "-"),
                host.get("hostname", "-"),
                host.get("vendor", "-"),
                host.get("role", "-"),
            )
        console.print(table_removed)

    if changed:
        table_changed = Table(title="Cambios de MAC", border_style="yellow")
        table_changed.add_column("IP", style="cyan")
        table_changed.add_column("MAC antigua", style="red")
        table_changed.add_column("MAC nueva", style="green")
        table_changed.add_column("Hostname anterior", style="white")
        table_changed.add_column("Hostname actual", style="white")
        for host in changed:
            table_changed.add_row(
                host.get("ip", "-"),
                host.get("old_mac", "-"),
                host.get("new_mac", "-"),
                host.get("old_hostname", "-"),
                host.get("new_hostname", "-"),
            )
        console.print(table_changed)

    if not added and not removed and not changed:
        console.print("[bold green]No hay diferencias entre ambos escaneos.[/bold green]")


def ensure_snapshot_dir(snapshot_dir: str) -> Path:
    path = Path(snapshot_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def snapshot_filename(subnet: str, label: Optional[str] = None) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    subnet_safe = subnet.replace("/", "_").replace(".", "-")
    if label:
        return f"{ts}_{slugify(label)}_{subnet_safe}.json"
    return f"{ts}_{subnet_safe}.json"


def save_snapshot(
    snapshot_dir: str,
    hosts: List[Dict[str, str]],
    interface: str,
    subnet: str,
    self_ip: str,
    gateway_ip: Optional[str],
    label: Optional[str] = None,
) -> Path:
    directory = ensure_snapshot_dir(snapshot_dir)
    filepath = directory / snapshot_filename(subnet, label)

    payload = build_scan_payload(
        hosts=hosts,
        interface=interface,
        subnet=subnet,
        self_ip=self_ip,
        gateway_ip=gateway_ip,
        label=label,
    )
    export_json_payload(str(filepath), payload)
    return filepath


def get_snapshot_files(snapshot_dir: str) -> List[Path]:
    directory = Path(snapshot_dir)
    if not directory.exists():
        return []
    return sorted(
        [p for p in directory.glob("*.json") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
    )


def get_latest_snapshot(snapshot_dir: str) -> Optional[Path]:
    files = get_snapshot_files(snapshot_dir)
    return files[-1] if files else None


def print_snapshots(snapshot_dir: str) -> None:
    files = get_snapshot_files(snapshot_dir)

    if not files:
        console.print(f"[yellow]No hay snapshots en '{snapshot_dir}'.[/yellow]")
        return

    table = Table(title=f"Snapshots en {snapshot_dir}")
    table.add_column("Fecha", style="cyan")
    table.add_column("Archivo", style="white")
    table.add_column("Hosts", style="green")
    table.add_column("Subred", style="magenta")
    table.add_column("Label", style="yellow")

    for file in files:
        try:
            data = load_scan_json(str(file))
            info = data.get("scan_info", {})
            table.add_row(
                info.get("timestamp", "-"),
                file.name,
                str(info.get("host_count", "-")),
                info.get("subnet", "-"),
                info.get("label", "-"),
            )
        except Exception:
            table.add_row("-", file.name, "-", "-", "JSON no válido")

    console.print(table)


def compare_with_latest_snapshot(snapshot_dir: str, current_hosts: List[Dict[str, str]]) -> None:
    latest = get_latest_snapshot(snapshot_dir)

    if latest is None:
        console.print("[yellow]No hay snapshot previo para comparar.[/yellow]")
        return

    old_data = load_scan_json(str(latest))
    old_hosts = old_data["hosts"]

    console.print(f"[cyan]Comparando contra el último snapshot:[/cyan] {latest}")
    diff = diff_scans(old_hosts, current_hosts)
    print_diff(diff)


def perform_scan(args) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    if args.subnet:
        subnet = str(ipaddress.IPv4Network(args.subnet, strict=False))
        ifname, self_ip, netmask = get_interface_data(args.interface)
    else:
        ifname, self_ip, netmask = get_interface_data(args.interface)
        subnet = str(calculate_network(self_ip, netmask))

    gateway_ip = get_default_gateway()

    raw_hosts = arp_scan(subnet, timeout=args.timeout)
    hosts = enrich_hosts(
        raw_hosts,
        self_ip=self_ip,
        gateway_ip=gateway_ip,
        resolve_names=args.resolve_names,
        vendor_lookup=args.vendor,
        include_self=args.include_self,
    )

    info = {
        "interface": ifname,
        "self_ip": self_ip,
        "netmask": netmask,
        "subnet": subnet,
        "gateway_ip": gateway_ip or "-",
    }

    return info, hosts


def print_watch_header(cycle: int, max_cycles: Optional[int], interval: int) -> None:
    suffix = f"/{max_cycles}" if max_cycles else ""
    text = (
        f"[bold cyan]Modo watch[/bold cyan] | "
        f"Ciclo [white]{cycle}{suffix}[/white] | "
        f"Intervalo [white]{interval}s[/white] | "
        f"[white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/white]"
    )
    console.print(Panel.fit(text, border_style="blue"))


# =========================
# SQLite
# =========================

def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            interface TEXT NOT NULL,
            subnet TEXT NOT NULL,
            self_ip TEXT NOT NULL,
            gateway_ip TEXT,
            host_count INTEGER NOT NULL,
            label TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            hostname TEXT,
            vendor TEXT,
            role TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)")

    conn.commit()
    conn.close()


def save_scan_to_db(
    db_path: str,
    info: Dict[str, str],
    hosts: List[Dict[str, str]],
    label: Optional[str] = None,
) -> int:
    init_db(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    timestamp = datetime.now().isoformat()

    cur.execute("""
        INSERT INTO scans (timestamp, interface, subnet, self_ip, gateway_ip, host_count, label)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        info["interface"],
        info["subnet"],
        info["self_ip"],
        info["gateway_ip"],
        len(hosts),
        label or "-"
    ))

    scan_id = cur.lastrowid

    for host in hosts:
        cur.execute("""
            INSERT INTO hosts (scan_id, ip, mac, hostname, vendor, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            host.get("ip", "-"),
            host.get("mac", "-"),
            host.get("hostname", "-"),
            host.get("vendor", "-"),
            host.get("role", "-"),
        ))

    conn.commit()
    conn.close()
    return int(scan_id)


def list_db_scans(db_path: str, limit: int = 20) -> None:
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, timestamp, interface, subnet, self_ip, gateway_ip, host_count, label
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cur.fetchall()
    conn.close()

    if not rows:
        console.print(f"[yellow]No hay escaneos guardados en la base de datos '{db_path}'.[/yellow]")
        return

    table = Table(title=f"Últimos escaneos en {db_path}")
    table.add_column("ID", style="cyan")
    table.add_column("Fecha", style="white")
    table.add_column("Interfaz", style="green")
    table.add_column("Subred", style="magenta")
    table.add_column("Self IP", style="blue")
    table.add_column("Gateway", style="yellow")
    table.add_column("Hosts", style="white")
    table.add_column("Label", style="red")

    for row in rows:
        table.add_row(*[str(x) for x in row])

    console.print(table)


def load_hosts_from_db(db_path: str, scan_id: int) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, timestamp, interface, subnet, self_ip, gateway_ip, host_count, label
        FROM scans
        WHERE id = ?
    """, (scan_id,))
    scan_row = cur.fetchone()

    if not scan_row:
        conn.close()
        raise ValueError(f"No existe un escaneo con ID {scan_id} en '{db_path}'.")

    cur.execute("""
        SELECT ip, mac, hostname, vendor, role
        FROM hosts
        WHERE scan_id = ?
        ORDER BY ip
    """, (scan_id,))
    host_rows = cur.fetchall()
    conn.close()

    info = {
        "id": str(scan_row[0]),
        "timestamp": scan_row[1],
        "interface": scan_row[2],
        "subnet": scan_row[3],
        "self_ip": scan_row[4],
        "gateway_ip": scan_row[5],
        "host_count": str(scan_row[6]),
        "label": scan_row[7],
    }

    hosts = []
    for row in host_rows:
        hosts.append({
            "ip": row[0],
            "mac": row[1],
            "hostname": row[2],
            "vendor": row[3],
            "role": row[4],
        })

    hosts = sorted(hosts, key=lambda x: tuple(map(int, x["ip"].split("."))))
    return info, hosts


def delete_scans_from_db(db_path: str, scan_ids: List[int]) -> Dict[str, int]:
    init_db(db_path)

    unique_ids = sorted(set(scan_ids))
    if not unique_ids:
        return {"requested": 0, "deleted_scans": 0, "deleted_hosts": 0}

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    placeholders = ",".join("?" for _ in unique_ids)

    cur.execute(
        f"SELECT COUNT(*) FROM hosts WHERE scan_id IN ({placeholders})",
        unique_ids
    )
    hosts_to_delete = cur.fetchone()[0]

    cur.execute(
        f"DELETE FROM hosts WHERE scan_id IN ({placeholders})",
        unique_ids
    )
    deleted_hosts = cur.rowcount

    cur.execute(
        f"DELETE FROM scans WHERE id IN ({placeholders})",
        unique_ids
    )
    deleted_scans = cur.rowcount

    conn.commit()
    conn.close()

    return {
        "requested": len(unique_ids),
        "deleted_scans": deleted_scans,
        "deleted_hosts": deleted_hosts if deleted_hosts != -1 else hosts_to_delete,
    }


# =========================
# HTML report
# =========================

def html_escape(value: str) -> str:
    return html.escape(str(value))


def render_hosts_table_html(hosts: List[Dict[str, str]]) -> str:
    rows = []
    for host in hosts:
        rows.append(f"""
        <tr>
            <td>{html_escape(host.get("ip", "-"))}</td>
            <td>{html_escape(host.get("mac", "-"))}</td>
            <td>{html_escape(host.get("hostname", "-"))}</td>
            <td>{html_escape(host.get("vendor", "-"))}</td>
            <td>{html_escape(host.get("role", "-"))}</td>
        </tr>
        """)
    return "\n".join(rows)


def render_diff_table_html(title: str, rows_data: List[Dict[str, str]], mode: str) -> str:
    if not rows_data:
        return f"<h3>{html_escape(title)}</h3><p>Sin resultados.</p>"

    if mode in ("added", "removed"):
        rows = []
        for host in rows_data:
            rows.append(f"""
            <tr>
                <td>{html_escape(host.get("ip", "-"))}</td>
                <td>{html_escape(host.get("mac", "-"))}</td>
                <td>{html_escape(host.get("hostname", "-"))}</td>
                <td>{html_escape(host.get("vendor", "-"))}</td>
                <td>{html_escape(host.get("role", "-"))}</td>
            </tr>
            """)
        body = "\n".join(rows)
        return f"""
        <h3>{html_escape(title)}</h3>
        <table>
            <thead>
                <tr>
                    <th>IP</th><th>MAC</th><th>HOSTNAME</th><th>VENDOR</th><th>ROLE</th>
                </tr>
            </thead>
            <tbody>{body}</tbody>
        </table>
        """

    rows = []
    for host in rows_data:
        rows.append(f"""
        <tr>
            <td>{html_escape(host.get("ip", "-"))}</td>
            <td>{html_escape(host.get("old_mac", "-"))}</td>
            <td>{html_escape(host.get("new_mac", "-"))}</td>
            <td>{html_escape(host.get("old_hostname", "-"))}</td>
            <td>{html_escape(host.get("new_hostname", "-"))}</td>
        </tr>
        """)
    body = "\n".join(rows)
    return f"""
    <h3>{html_escape(title)}</h3>
    <table>
        <thead>
            <tr>
                <th>IP</th><th>MAC antigua</th><th>MAC nueva</th><th>Hostname anterior</th><th>Hostname actual</th>
            </tr>
        </thead>
        <tbody>{body}</tbody>
    </table>
    """


def generate_html_report(
    filepath: str,
    info: Dict[str, str],
    hosts: List[Dict[str, str]],
    diff: Optional[Dict[str, List[Dict[str, str]]]] = None,
    title: str = "Kanshi Report",
) -> None:
    added_count = len(diff["added"]) if diff else 0
    removed_count = len(diff["removed"]) if diff else 0
    changed_count = len(diff["changed"]) if diff else 0

    diff_section = ""
    if diff is not None:
        diff_section = f"""
        <section>
            <h2>Resumen del diff</h2>
            <div class="cards">
                <div class="card"><strong>Hosts nuevos</strong><span>{added_count}</span></div>
                <div class="card"><strong>Hosts desaparecidos</strong><span>{removed_count}</span></div>
                <div class="card"><strong>Cambios de MAC</strong><span>{changed_count}</span></div>
            </div>
            {render_diff_table_html("Hosts nuevos", diff["added"], "added")}
            {render_diff_table_html("Hosts desaparecidos", diff["removed"], "removed")}
            {render_diff_table_html("Cambios de MAC", diff["changed"], "changed")}
        </section>
        """

    html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>{html_escape(title)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
            margin: 0;
            padding: 24px;
        }}
        h1, h2, h3 {{
            color: #93c5fd;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin: 16px 0 24px 0;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 16px;
        }}
        .card span {{
            display: block;
            margin-top: 8px;
            font-size: 24px;
            font-weight: bold;
            color: #34d399;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
            background: #111827;
            border-radius: 12px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px;
            border-bottom: 1px solid #1f2937;
            text-align: left;
            font-size: 14px;
        }}
        th {{
            background: #1e293b;
            color: #93c5fd;
        }}
        tr:hover {{
            background: #172033;
        }}
        .meta {{
            margin-bottom: 24px;
        }}
        .meta p {{
            margin: 6px 0;
        }}
        .footer {{
            margin-top: 40px;
            color: #9ca3af;
            font-size: 12px;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>{html_escape(title)}</h1>

    <section class="meta">
        <h2>Información del escaneo</h2>
        <p><strong>Fecha:</strong> {html_escape(datetime.now().isoformat())}</p>
        <p><strong>Interfaz:</strong> {html_escape(info.get("interface", "-"))}</p>
        <p><strong>Subred:</strong> {html_escape(info.get("subnet", "-"))}</p>
        <p><strong>IP local:</strong> {html_escape(info.get("self_ip", "-"))}</p>
        <p><strong>Gateway:</strong> {html_escape(info.get("gateway_ip", "-"))}</p>
        <p><strong>Total hosts:</strong> {html_escape(str(len(hosts)))}</p>
    </section>

    <section>
        <h2>Hosts detectados</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>HOSTNAME</th>
                    <th>VENDOR</th>
                    <th>ROLE</th>
                </tr>
            </thead>
            <tbody>
                {render_hosts_table_html(hosts)}
            </tbody>
        </table>
    </section>

    {diff_section}

    <div class="footer">
        Informe generado por Kanshi v6
    </div>
</div>
</body>
</html>
"""
    Path(filepath).write_text(html_doc, encoding="utf-8")


def run_watch_mode(args) -> None:
    previous_hosts: Optional[List[Dict[str, str]]] = None
    baseline_label = "ciclo anterior"

    if args.compare_last:
        latest = get_latest_snapshot(args.snapshot_dir)
        if latest is not None:
            data = load_scan_json(str(latest))
            previous_hosts = data["hosts"]
            baseline_label = f"último snapshot ({latest.name})"

    cycle = 0

    while True:
        cycle += 1

        if not args.no_clear:
            console.clear()

        print_banner()
        print_watch_header(cycle, args.max_cycles, args.interval)

        info, hosts = perform_scan(args)

        print_scan_info(
            info["interface"],
            info["self_ip"],
            info["netmask"],
            info["subnet"],
            info["gateway_ip"] if info["gateway_ip"] != "-" else None,
        )

        diff = diff_scans(previous_hosts, hosts) if previous_hosts is not None else None
        has_changes = diff_has_changes(diff) if diff is not None else False

        if not args.watch_changes_only:
            print_results(
                hosts,
                show_hostnames=args.resolve_names,
                show_vendor=args.vendor,
            )

        if diff is None:
            console.print("[cyan]No había baseline previa. Este ciclo pasa a ser la referencia inicial.[/cyan]")
        else:
            console.print(f"[cyan]Comparando contra:[/cyan] {baseline_label}")
            if has_changes:
                if args.watch_changes_only:
                    print_results(
                        hosts,
                        show_hostnames=args.resolve_names,
                        show_vendor=args.vendor,
                    )
                print_diff(diff)

                if args.beep:
                    print("\a", end="", flush=True)
            else:
                console.print("[green]Sin cambios detectados.[/green]")

        if args.db_path:
            scan_id = save_scan_to_db(args.db_path, info, hosts, label=args.label)
            console.print(f"[green]Escaneo guardado en SQLite con ID: {scan_id}[/green]")

        if args.json_out:
            export_json(
                args.json_out,
                hosts,
                interface=info["interface"],
                subnet=info["subnet"],
                self_ip=info["self_ip"],
                gateway_ip=None if info["gateway_ip"] == "-" else info["gateway_ip"],
                label=args.label,
            )
            console.print(f"[green]JSON actualizado en: {args.json_out}[/green]")

        if args.csv_out:
            export_csv(args.csv_out, hosts)
            console.print(f"[green]CSV actualizado en: {args.csv_out}[/green]")

        if args.snapshot:
            snapshot_path = save_snapshot(
                snapshot_dir=args.snapshot_dir,
                hosts=hosts,
                interface=info["interface"],
                subnet=info["subnet"],
                self_ip=info["self_ip"],
                gateway_ip=None if info["gateway_ip"] == "-" else info["gateway_ip"],
                label=args.label,
            )
            console.print(f"[green]Snapshot guardado en: {snapshot_path}[/green]")
        elif args.save_on_change and diff is not None and has_changes:
            snapshot_path = save_snapshot(
                snapshot_dir=args.snapshot_dir,
                hosts=hosts,
                interface=info["interface"],
                subnet=info["subnet"],
                self_ip=info["self_ip"],
                gateway_ip=None if info["gateway_ip"] == "-" else info["gateway_ip"],
                label=args.label or "watch-change",
            )
            console.print(f"[green]Snapshot guardado por cambio en: {snapshot_path}[/green]")

        if args.html_out:
            generate_html_report(
                filepath=args.html_out,
                info=info,
                hosts=hosts,
                diff=diff if diff is not None else None,
                title=f"Kanshi Watch Report - Cycle {cycle}",
            )
            console.print(f"[green]Informe HTML actualizado en: {args.html_out}[/green]")

        previous_hosts = hosts
        baseline_label = "ciclo anterior"

        if args.max_cycles and cycle >= args.max_cycles:
            console.print("[bold cyan]Modo watch finalizado: se alcanzó el número máximo de ciclos.[/bold cyan]")
            break

        time.sleep(args.interval)


def main():
    parser = argparse.ArgumentParser(
        description="Kanshi v6 - Descubrimiento de hosts activos por ARP con snapshots, SQLite e informes HTML."
    )
    parser.add_argument("--interface", help="Interfaz de red a usar (ej. eth0, wlan0).")
    parser.add_argument("--subnet", help="Subred manual (ej. 192.168.1.0/24).")
    parser.add_argument("--timeout", type=int, default=1, help="Tiempo de espera ARP.")
    parser.add_argument("--resolve-names", action="store_true", help="Resolver hostname por DNS inversa.")
    parser.add_argument("--vendor", action="store_true", help="Intentar detectar fabricante por MAC.")
    parser.add_argument("--include-self", action="store_true", help="Incluir tu propia IP en la salida si aparece.")
    parser.add_argument("--json-out", help="Exportar resultados a JSON.")
    parser.add_argument("--csv-out", help="Exportar resultados a CSV.")
    parser.add_argument("--html-out", help="Generar informe HTML del escaneo actual.")
    parser.add_argument("--diff", nargs=2, metavar=("OLD_SCAN", "NEW_SCAN"), help="Comparar dos escaneos JSON exportados por Kanshi.")
    parser.add_argument("--snapshot", action="store_true", help="Guardar snapshot del escaneo actual. En watch, guarda uno por ciclo.")
    parser.add_argument("--compare-last", action="store_true", help="Comparar contra el último snapshot. En watch, solo se usa como baseline inicial.")
    parser.add_argument("--list-snapshots", action="store_true", help="Listar snapshots guardados y salir.")
    parser.add_argument("--snapshot-dir", default="scans", help="Directorio donde guardar/cargar snapshots. Por defecto: scans")
    parser.add_argument("--label", help="Etiqueta opcional para snapshots o base de datos.")
    parser.add_argument("--watch", action="store_true", help="Modo vigilancia: repite el escaneo periódicamente.")
    parser.add_argument("--interval", type=int, default=30, help="Segundos entre escaneos en modo watch.")
    parser.add_argument("--watch-changes-only", action="store_true", help="En modo watch, mostrar detalles solo si hay cambios.")
    parser.add_argument("--save-on-change", action="store_true", help="En modo watch, guardar snapshot solo cuando haya cambios.")
    parser.add_argument("--beep", action="store_true", help="Emitir un pitido al detectar cambios en modo watch.")
    parser.add_argument("--max-cycles", type=int, help="Número máximo de ciclos en modo watch.")
    parser.add_argument("--no-clear", action="store_true", help="En modo watch, no limpiar la pantalla en cada ciclo.")

    parser.add_argument("--db-path", default="kanshi.db", help="Ruta de la base de datos SQLite. Por defecto: kanshi.db")
    parser.add_argument("--db-save", action="store_true", help="Guardar el escaneo actual en SQLite.")
    parser.add_argument("--db-list", action="store_true", help="Listar escaneos guardados en SQLite.")
    parser.add_argument("--db-limit", type=int, default=20, help="Número máximo de escaneos a listar desde SQLite.")
    parser.add_argument("--db-diff", nargs=2, type=int, metavar=("SCAN_ID_1", "SCAN_ID_2"), help="Comparar dos escaneos guardados en SQLite por ID.")
    parser.add_argument("--db-remove", nargs="+", type=int, metavar="SCAN_ID", help="Eliminar uno o varios escaneos de SQLite por ID.")
    parser.add_argument("--yes", action="store_true", help="Confirma acciones destructivas sin pedir validación interactiva.")

    args = parser.parse_args()

    try:
        print_banner()

        if args.interval < 1:
            raise ValueError("El intervalo debe ser mayor o igual que 1 segundo.")

        if args.vendor and manuf is None:
            console.print("[yellow]'manuf' no está instalado. La columna VENDOR mostrará '-'.[/yellow]")
            console.print("[yellow]Instálalo con: pip install manuf[/yellow]")

        if args.list_snapshots:
            print_snapshots(args.snapshot_dir)
            return

        if args.db_remove:
            ids = sorted(set(args.db_remove))

            if not args.yes:
                confirm = input(
                    f"Vas a eliminar {len(ids)} scan(s) de '{args.db_path}' con IDs {ids}. "
                    "Escribe DELETE para confirmar: "
                ).strip()

                if confirm != "DELETE":
                    console.print("[yellow]Operación cancelada.[/yellow]")
                    return

            result = delete_scans_from_db(args.db_path, ids)

            console.print(
                f"[green]Eliminados {result['deleted_scans']} scan(s) "
                f"y {result['deleted_hosts']} host(s) asociados.[/green]"
            )
            return

        if args.db_list:
            list_db_scans(args.db_path, args.db_limit)
            return

        if args.db_diff:
            scan1, scan2 = args.db_diff
            info1, hosts1 = load_hosts_from_db(args.db_path, scan1)
            info2, hosts2 = load_hosts_from_db(args.db_path, scan2)

            console.print(f"[cyan]Comparando scans SQLite:[/cyan] {scan1} -> {scan2}")
            diff = diff_scans(hosts1, hosts2)
            print_diff(diff)

            if args.html_out:
                generate_html_report(
                    filepath=args.html_out,
                    info=info2,
                    hosts=hosts2,
                    diff=diff,
                    title=f"Kanshi SQLite Diff Report ({scan1} vs {scan2})",
                )
                console.print(f"[green]Informe HTML generado en: {args.html_out}[/green]")
            return

        if args.diff:
            old_file, new_file = args.diff
            old_data = load_scan_json(old_file)
            new_data = load_scan_json(new_file)
            diff = diff_scans(old_data["hosts"], new_data["hosts"])
            print_diff(diff)

            if args.html_out:
                generate_html_report(
                    filepath=args.html_out,
                    info=new_data.get("scan_info", {}),
                    hosts=new_data["hosts"],
                    diff=diff,
                    title="Kanshi JSON Diff Report",
                )
                console.print(f"[green]Informe HTML generado en: {args.html_out}[/green]")
            return

        if args.watch:
            run_watch_mode(args)
            return

        info, hosts = perform_scan(args)

        print_scan_info(
            info["interface"],
            info["self_ip"],
            info["netmask"],
            info["subnet"],
            info["gateway_ip"] if info["gateway_ip"] != "-" else None,
        )

        print_results(
            hosts,
            show_hostnames=args.resolve_names,
            show_vendor=args.vendor,
        )

        diff_for_report = None

        if args.compare_last:
            console.print()
            latest = get_latest_snapshot(args.snapshot_dir)
            if latest is None:
                console.print("[yellow]No hay snapshot previo para comparar.[/yellow]")
            else:
                old_data = load_scan_json(str(latest))
                diff_for_report = diff_scans(old_data["hosts"], hosts)
                console.print(f"[cyan]Comparando contra el último snapshot:[/cyan] {latest}")
                print_diff(diff_for_report)

        if args.db_save:
            scan_id = save_scan_to_db(args.db_path, info, hosts, label=args.label)
            console.print(f"[green]Escaneo guardado en SQLite con ID: {scan_id}[/green]")

        if args.json_out:
            export_json(
                args.json_out,
                hosts,
                interface=info["interface"],
                subnet=info["subnet"],
                self_ip=info["self_ip"],
                gateway_ip=None if info["gateway_ip"] == "-" else info["gateway_ip"],
                label=args.label,
            )
            console.print(f"[green]JSON exportado a: {args.json_out}[/green]")

        if args.csv_out:
            export_csv(args.csv_out, hosts)
            console.print(f"[green]CSV exportado a: {args.csv_out}[/green]")

        if args.snapshot:
            snapshot_path = save_snapshot(
                snapshot_dir=args.snapshot_dir,
                hosts=hosts,
                interface=info["interface"],
                subnet=info["subnet"],
                self_ip=info["self_ip"],
                gateway_ip=None if info["gateway_ip"] == "-" else info["gateway_ip"],
                label=args.label,
            )
            console.print(f"[green]Snapshot guardado en: {snapshot_path}[/green]")

        if args.html_out:
            generate_html_report(
                filepath=args.html_out,
                info=info,
                hosts=hosts,
                diff=diff_for_report,
                title="Kanshi Scan Report",
            )
            console.print(f"[green]Informe HTML generado en: {args.html_out}[/green]")

    except KeyboardInterrupt:
        console.print("\n[red]Escaneo cancelado por el usuario.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()