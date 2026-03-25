#!/usr/bin/env python3

import argparse
import csv
import io
import json
import sqlite3
from typing import Dict, List

from flask import Flask, abort, jsonify, make_response, redirect, render_template_string, request, url_for


BASE_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root{
      --bg:#0f172a;
      --panel:#111827;
      --panel-2:#1f2937;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --blue:#93c5fd;
      --green:#34d399;
      --red:#f87171;
      --yellow:#fbbf24;
      --border:#243244;
    }
    * { box-sizing: border-box; }
    body{
      margin:0;
      font-family: Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    a{
      color: var(--blue);
      text-decoration:none;
    }
    a:hover{
      text-decoration:underline;
    }
    .container{
      max-width: 1380px;
      margin: 0 auto;
      padding: 24px;
    }
    .topbar{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:16px;
      flex-wrap:wrap;
      margin-bottom: 24px;
    }
    .brand{
      font-size: 28px;
      font-weight: bold;
      color: var(--blue);
    }
    .subtitle{
      color: var(--muted);
      font-size: 14px;
    }
    .panel{
      background: var(--panel);
      border:1px solid var(--border);
      border-radius:16px;
      padding:20px;
      margin-bottom:24px;
    }
    .cards{
      display:grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap:16px;
      margin-bottom:24px;
    }
    .card{
      background: var(--panel);
      border:1px solid var(--border);
      border-radius:16px;
      padding:18px;
    }
    .card .label{
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 8px;
    }
    .card .value{
      font-size: 24px;
      font-weight: bold;
      color: var(--green);
      word-break: break-word;
    }
    table{
      width:100%;
      border-collapse: collapse;
      margin-top: 12px;
      background: var(--panel);
      border-radius: 14px;
      overflow:hidden;
    }
    th, td{
      padding: 12px;
      text-align: left;
      border-bottom:1px solid var(--border);
      font-size: 14px;
      vertical-align: top;
    }
    th{
      background: var(--panel-2);
      color: var(--blue);
    }
    tr:hover td{
      background:#172033;
    }
    .tag{
      display:inline-block;
      padding:4px 8px;
      border-radius:999px;
      font-size:12px;
      background:#1e293b;
      border:1px solid var(--border);
      color: var(--text);
      white-space: nowrap;
    }
    .ok{ color: var(--green); }
    .warn{ color: var(--yellow); }
    .danger{ color: var(--red); }
    form.inline{
      display:flex;
      gap:12px;
      flex-wrap:wrap;
      align-items:end;
    }
    label{
      display:flex;
      flex-direction:column;
      gap:6px;
      font-size:14px;
      color: var(--muted);
    }
    input, select{
      background:#0b1220;
      border:1px solid var(--border);
      color:var(--text);
      padding:10px 12px;
      border-radius:10px;
      min-width:120px;
    }
    button{
      background: var(--blue);
      color:#0b1220;
      border:none;
      padding:11px 16px;
      border-radius:10px;
      cursor:pointer;
      font-weight:bold;
    }
    button:hover{
      opacity:.92;
    }
    .muted{
      color:var(--muted);
    }
    .section-title{
      margin:0 0 12px 0;
      font-size:20px;
      color: var(--blue);
    }
    .actions{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      align-items:center;
    }
    .actions a{
      white-space: nowrap;
    }
    .btn-link{
      display:inline-block;
      padding:8px 12px;
      border-radius:10px;
      background:#1e293b;
      border:1px solid var(--border);
      color:var(--text);
    }
    .pagination{
      display:flex;
      gap:10px;
      margin-top:16px;
      flex-wrap:wrap;
    }
    canvas{
      background:#111827;
      border:1px solid var(--border);
      border-radius:16px;
      padding:16px;
    }
    .mono{
      font-family: Consolas, monospace;
    }
    .btn-danger{
        background: #7f1d1d;
        color: #fee2e2;
        border: 1px solid #b91c1c;
        padding: 8px 12px;
        border-radius: 10px;
        cursor: pointer;
        font-weight: bold;
    }
    .btn-danger:hover{
        opacity: .92;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div>
        <div class="brand">Kanshi v9</div>
        <div class="subtitle">Dashboard local con histórico de escaneos e inventario persistente de hosts</div>
      </div>
      <div class="actions">
        <a href="/" class="btn-link">Inicio</a>
        <a href="/hosts" class="btn-link">Inventario</a>
      </div>
    </div>

    {{ body|safe }}
  </div>
</body>
</html>
"""


INDEX_BODY = """
<div class="cards">
  <div class="card">
    <div class="label">Base de datos</div>
    <div class="value">{{ db_path }}</div>
  </div>
  <div class="card">
    <div class="label">Escaneos guardados</div>
    <div class="value">{{ total_scans }}</div>
  </div>
  <div class="card">
    <div class="label">Hosts registrados</div>
    <div class="value">{{ total_hosts }}</div>
  </div>
  <div class="card">
    <div class="label">MACs distintas</div>
    <div class="value">{{ total_distinct_macs }}</div>
  </div>
  <div class="card">
    <div class="label">Último escaneo</div>
    <div class="value">{{ latest_scan_timestamp or "-" }}</div>
  </div>
</div>

<div class="panel">
  <h2 class="section-title">Filtros</h2>
  <form class="inline" method="get" action="/">
    <label>
      Label
      <select name="label">
        <option value="">Todas</option>
        {% for lbl in labels %}
          <option value="{{ lbl }}" {% if current_label == lbl %}selected{% endif %}>{{ lbl }}</option>
        {% endfor %}
      </select>
    </label>

    <label>
      Buscar
      <input type="text" name="q" value="{{ current_q or '' }}" placeholder="ID, IP, MAC, hostname, vendor, role, label">
    </label>

    <label>
      Límite
      <select name="limit">
        {% for n in [10,20,50,100] %}
          <option value="{{ n }}" {% if limit == n %}selected{% endif %}>{{ n }}</option>
        {% endfor %}
      </select>
    </label>

    <input type="hidden" name="page" value="1">
    <button type="submit">Aplicar</button>
  </form>
</div>

<div class="panel">
  <h2 class="section-title">Comparar dos escaneos</h2>
  <form class="inline" method="get" action="/compare">
    <label>
      Scan ID 1
      <input type="number" name="scan1" required>
    </label>
    <label>
      Scan ID 2
      <input type="number" name="scan2" required>
    </label>
    <button type="submit">Comparar</button>
  </form>
</div>

<div class="panel">
  <h2 class="section-title">Evolución de hosts</h2>
  <canvas id="hostsChart" height="120"></canvas>
</div>

<div class="panel">
  <h2 class="section-title">Últimos cambios entre escaneos consecutivos</h2>
  {% if recent_changes %}
  <table>
    <thead>
      <tr>
        <th>Origen</th>
        <th>Destino</th>
        <th>Fecha destino</th>
        <th>Nuevos</th>
        <th>Desaparecidos</th>
        <th>Cambios MAC</th>
        <th>Acción</th>
      </tr>
    </thead>
    <tbody>
      {% for item in recent_changes %}
      <tr>
        <td>{{ item.scan1_id }}</td>
        <td>{{ item.scan2_id }}</td>
        <td>{{ item.timestamp }}</td>
        <td class="ok">{{ item.added }}</td>
        <td class="danger">{{ item.removed }}</td>
        <td class="warn">{{ item.changed }}</td>
        <td><a href="/compare?scan1={{ item.scan1_id }}&scan2={{ item.scan2_id }}">Ver diff</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay suficientes escaneos para calcular cambios recientes.</p>
  {% endif %}
</div>

<div class="panel">
  <h2 class="section-title">Escaneos</h2>
  {% if scans %}
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Fecha</th>
        <th>Interfaz</th>
        <th>Subred</th>
        <th>Self IP</th>
        <th>Gateway</th>
        <th>Hosts</th>
        <th>Label</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
      {% for s in scans %}
      <tr>
        <td>{{ s.id }}</td>
        <td>{{ s.timestamp }}</td>
        <td>{{ s.interface }}</td>
        <td>{{ s.subnet }}</td>
        <td>{{ s.self_ip }}</td>
        <td>{{ s.gateway_ip }}</td>
        <td>{{ s.host_count }}</td>
        <td><span class="tag">{{ s.label }}</span></td>
        <td>
            <div class="actions">
                <a href="/scan/{{ s.id }}">Detalle</a>
                <a href="/scan/{{ s.id }}/json">JSON</a>
                <a href="/scan/{{ s.id }}/csv">CSV</a>

                <form method="post"
                    action="/scan/{{ s.id }}/delete"
                    onsubmit="return confirm('¿Seguro que quieres borrar el scan {{ s.id }} y todos sus hosts asociados?');"
                    style="display:inline;">
                <input type="hidden" name="next" value="{{ request.full_path }}">
                <button type="submit" class="btn-danger">Borrar</button>
                </form>
            </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="pagination">
    {% if page > 1 %}
      <a class="btn-link" href="/?page={{ page - 1 }}&limit={{ limit }}&label={{ current_label or '' }}&q={{ current_q or '' }}">Anterior</a>
    {% endif %}
    {% if has_next %}
      <a class="btn-link" href="/?page={{ page + 1 }}&limit={{ limit }}&label={{ current_label or '' }}&q={{ current_q or '' }}">Siguiente</a>
    {% endif %}
  </div>
  {% else %}
    <p class="muted">No hay escaneos que coincidan con los filtros.</p>
  {% endif %}
</div>

<script>
  const chartLabels = {{ chart_labels|safe }};
  const chartData = {{ chart_values|safe }};

  const ctx = document.getElementById('hostsChart');
  if (ctx && chartLabels.length > 0) {
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: chartLabels,
        datasets: [{
          label: 'Hosts detectados',
          data: chartData,
          tension: 0.2,
          borderWidth: 2,
          fill: false
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            labels: { color: '#e5e7eb' }
          }
        },
        scales: {
          x: {
            ticks: { color: '#9ca3af' },
            grid: { color: '#243244' }
          },
          y: {
            ticks: { color: '#9ca3af', precision: 0 },
            grid: { color: '#243244' }
          }
        }
      }
    });
  }
</script>
"""


SCAN_BODY = """
<div class="cards">
  <div class="card">
    <div class="label">Scan ID</div>
    <div class="value">{{ scan.id }}</div>
  </div>
  <div class="card">
    <div class="label">Fecha</div>
    <div class="value">{{ scan.timestamp }}</div>
  </div>
  <div class="card">
    <div class="label">Hosts detectados</div>
    <div class="value">{{ scan.host_count }}</div>
  </div>
  <div class="card">
    <div class="label">Label</div>
    <div class="value">{{ scan.label }}</div>
  </div>
</div>

<div class="panel">
  <div class="actions">
    <a class="btn-link" href="/scan/{{ scan.id }}/json">Descargar JSON</a>
    <a class="btn-link" href="/scan/{{ scan.id }}/csv">Descargar CSV</a>

    <form method="post"
            action="/scan/{{ scan.id }}/delete"
            onsubmit="return confirm('¿Seguro que quieres borrar el scan {{ scan.id }} y todos sus hosts asociados?');"
            style="display:inline;">
        <input type="hidden" name="next" value="/">
        <button type="submit" class="btn-danger">Borrar scan</button>
    </form>
  </div>
</div>

<div class="panel">
  <h2 class="section-title">Información del escaneo</h2>
  <table>
    <tbody>
      <tr><th>ID</th><td>{{ scan.id }}</td></tr>
      <tr><th>Fecha</th><td>{{ scan.timestamp }}</td></tr>
      <tr><th>Interfaz</th><td>{{ scan.interface }}</td></tr>
      <tr><th>Subred</th><td>{{ scan.subnet }}</td></tr>
      <tr><th>Self IP</th><td>{{ scan.self_ip }}</td></tr>
      <tr><th>Gateway</th><td>{{ scan.gateway_ip }}</td></tr>
      <tr><th>Label</th><td>{{ scan.label }}</td></tr>
    </tbody>
  </table>
</div>

<div class="panel">
  <h2 class="section-title">Hosts del escaneo</h2>
  {% if hosts %}
  <table>
    <thead>
      <tr>
        <th>IP</th>
        <th>MAC</th>
        <th>HOSTNAME</th>
        <th>VENDOR</th>
        <th>ROLE</th>
        <th>Histórico</th>
      </tr>
    </thead>
    <tbody>
      {% for h in hosts %}
      <tr>
        <td><a class="mono" href="/host/ip/{{ h.ip }}">{{ h.ip }}</a></td>
        <td><a class="mono" href="/host/mac/{{ h.mac }}">{{ h.mac }}</a></td>
        <td>{{ h.hostname }}</td>
        <td>{{ h.vendor }}</td>
        <td>{{ h.role }}</td>
        <td>
          <div class="actions">
            <a href="/host/mac/{{ h.mac }}">MAC</a>
            <a href="/host/ip/{{ h.ip }}">IP</a>
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay hosts asociados a este escaneo.</p>
  {% endif %}
</div>
"""


COMPARE_BODY = """
<div class="cards">
  <div class="card">
    <div class="label">Scan origen</div>
    <div class="value">{{ scan1.id }}</div>
  </div>
  <div class="card">
    <div class="label">Scan destino</div>
    <div class="value">{{ scan2.id }}</div>
  </div>
  <div class="card">
    <div class="label">Hosts nuevos</div>
    <div class="value">{{ diff.added|length }}</div>
  </div>
  <div class="card">
    <div class="label">Hosts desaparecidos</div>
    <div class="value">{{ diff.removed|length }}</div>
  </div>
  <div class="card">
    <div class="label">Cambios de MAC</div>
    <div class="value">{{ diff.changed|length }}</div>
  </div>
</div>

<div class="panel">
  <h2 class="section-title">Contexto</h2>
  <p><strong>Scan 1:</strong> <a href="/scan/{{ scan1.id }}">{{ scan1.id }}</a> — {{ scan1.timestamp }} — {{ scan1.subnet }}</p>
  <p><strong>Scan 2:</strong> <a href="/scan/{{ scan2.id }}">{{ scan2.id }}</a> — {{ scan2.timestamp }} — {{ scan2.subnet }}</p>
</div>

<div class="panel">
  <h2 class="section-title">Hosts nuevos</h2>
  {% if diff.added %}
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
      {% for h in diff.added %}
      <tr>
        <td class="ok"><a href="/host/ip/{{ h.ip }}">{{ h.ip }}</a></td>
        <td><a href="/host/mac/{{ h.mac }}">{{ h.mac }}</a></td>
        <td>{{ h.hostname }}</td>
        <td>{{ h.vendor }}</td>
        <td>{{ h.role }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay hosts nuevos.</p>
  {% endif %}
</div>

<div class="panel">
  <h2 class="section-title">Hosts desaparecidos</h2>
  {% if diff.removed %}
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
      {% for h in diff.removed %}
      <tr>
        <td class="danger"><a href="/host/ip/{{ h.ip }}">{{ h.ip }}</a></td>
        <td><a href="/host/mac/{{ h.mac }}">{{ h.mac }}</a></td>
        <td>{{ h.hostname }}</td>
        <td>{{ h.vendor }}</td>
        <td>{{ h.role }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay hosts desaparecidos.</p>
  {% endif %}
</div>

<div class="panel">
  <h2 class="section-title">Cambios de MAC</h2>
  {% if diff.changed %}
  <table>
    <thead>
      <tr>
        <th>IP</th>
        <th>MAC antigua</th>
        <th>MAC nueva</th>
        <th>Hostname anterior</th>
        <th>Hostname actual</th>
      </tr>
    </thead>
    <tbody>
      {% for h in diff.changed %}
      <tr>
        <td class="warn"><a href="/host/ip/{{ h.ip }}">{{ h.ip }}</a></td>
        <td>{{ h.old_mac }}</td>
        <td>{{ h.new_mac }}</td>
        <td>{{ h.old_hostname }}</td>
        <td>{{ h.new_hostname }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay cambios de MAC.</p>
  {% endif %}
</div>
"""


HOSTS_BODY = """
<div class="cards">
  <div class="card">
    <div class="label">MACs visibles con los filtros</div>
    <div class="value">{{ total_inventory }}</div>
  </div>
  <div class="card">
    <div class="label">Filtro label</div>
    <div class="value">{{ current_label or "Todas" }}</div>
  </div>
  <div class="card">
    <div class="label">Búsqueda</div>
    <div class="value">{{ current_q or "-" }}</div>
  </div>
</div>

<div class="panel">
  <h2 class="section-title">Filtros de inventario</h2>
  <form class="inline" method="get" action="/hosts">
    <label>
      Label
      <select name="label">
        <option value="">Todas</option>
        {% for lbl in labels %}
          <option value="{{ lbl }}" {% if current_label == lbl %}selected{% endif %}>{{ lbl }}</option>
        {% endfor %}
      </select>
    </label>

    <label>
      Buscar
      <input type="text" name="q" value="{{ current_q or '' }}" placeholder="MAC, IP, hostname, vendor, role, label">
    </label>

    <label>
      Límite
      <select name="limit">
        {% for n in [10,20,50,100] %}
          <option value="{{ n }}" {% if limit == n %}selected{% endif %}>{{ n }}</option>
        {% endfor %}
      </select>
    </label>

    <input type="hidden" name="page" value="1">
    <button type="submit">Aplicar</button>
  </form>
</div>

<div class="panel">
  <h2 class="section-title">Inventario histórico</h2>
  {% if items %}
  <table>
    <thead>
      <tr>
        <th>MAC</th>
        <th>Último hostname</th>
        <th>Último vendor</th>
        <th>Último role</th>
        <th>Veces visto</th>
        <th>IPs distintas</th>
        <th>Primera vez</th>
        <th>Última vez</th>
        <th>Última label</th>
        <th>Acción</th>
      </tr>
    </thead>
    <tbody>
      {% for item in items %}
      <tr>
        <td class="mono"><a href="/host/mac/{{ item.mac }}">{{ item.mac }}</a></td>
        <td>{{ item.latest_hostname }}</td>
        <td>{{ item.latest_vendor }}</td>
        <td>{{ item.latest_role }}</td>
        <td>{{ item.sightings }}</td>
        <td>{{ item.distinct_ips }}</td>
        <td>{{ item.first_seen }}</td>
        <td>{{ item.last_seen }}</td>
        <td><span class="tag">{{ item.latest_label }}</span></td>
        <td><a href="/host/mac/{{ item.mac }}">Ver histórico</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="pagination">
    {% if page > 1 %}
      <a class="btn-link" href="/hosts?page={{ page - 1 }}&limit={{ limit }}&label={{ current_label or '' }}&q={{ current_q or '' }}">Anterior</a>
    {% endif %}
    {% if has_next %}
      <a class="btn-link" href="/hosts?page={{ page + 1 }}&limit={{ limit }}&label={{ current_label or '' }}&q={{ current_q or '' }}">Siguiente</a>
    {% endif %}
  </div>
  {% else %}
    <p class="muted">No hay hosts que coincidan con los filtros.</p>
  {% endif %}
</div>
"""


HOST_MAC_BODY = """
<div class="cards">
  <div class="card">
    <div class="label">MAC</div>
    <div class="value mono">{{ mac }}</div>
  </div>
  <div class="card">
    <div class="label">Veces visto</div>
    <div class="value">{{ summary.sightings }}</div>
  </div>
  <div class="card">
    <div class="label">IPs distintas</div>
    <div class="value">{{ summary.distinct_ips }}</div>
  </div>
  <div class="card">
    <div class="label">Primera vez</div>
    <div class="value">{{ summary.first_seen }}</div>
  </div>
  <div class="card">
    <div class="label">Última vez</div>
    <div class="value">{{ summary.last_seen }}</div>
  </div>
</div>

<div class="panel">
  <h2 class="section-title">Resumen del host</h2>
  <table>
    <tbody>
      <tr><th>MAC</th><td class="mono">{{ mac }}</td></tr>
      <tr><th>Último hostname</th><td>{{ summary.latest_hostname }}</td></tr>
      <tr><th>Último vendor</th><td>{{ summary.latest_vendor }}</td></tr>
      <tr><th>Último role</th><td>{{ summary.latest_role }}</td></tr>
      <tr><th>Última label</th><td>{{ summary.latest_label }}</td></tr>
      <tr><th>IPs observadas</th><td>{{ summary.ip_list }}</td></tr>
    </tbody>
  </table>
</div>

<div class="panel">
  <h2 class="section-title">Apariciones del host</h2>
  {% if sightings %}
  <table>
    <thead>
      <tr>
        <th>Scan ID</th>
        <th>Fecha</th>
        <th>Label</th>
        <th>Subred</th>
        <th>IP</th>
        <th>Hostname</th>
        <th>Vendor</th>
        <th>Role</th>
      </tr>
    </thead>
    <tbody>
      {% for row in sightings %}
      <tr>
        <td><a href="/scan/{{ row.scan_id }}">{{ row.scan_id }}</a></td>
        <td>{{ row.timestamp }}</td>
        <td><span class="tag">{{ row.label }}</span></td>
        <td>{{ row.subnet }}</td>
        <td><a href="/host/ip/{{ row.ip }}">{{ row.ip }}</a></td>
        <td>{{ row.hostname }}</td>
        <td>{{ row.vendor }}</td>
        <td>{{ row.role }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay apariciones registradas.</p>
  {% endif %}
</div>
"""


HOST_IP_BODY = """
<div class="cards">
  <div class="card">
    <div class="label">IP</div>
    <div class="value mono">{{ ip }}</div>
  </div>
  <div class="card">
    <div class="label">Veces vista</div>
    <div class="value">{{ summary.sightings }}</div>
  </div>
  <div class="card">
    <div class="label">MACs distintas</div>
    <div class="value">{{ summary.distinct_macs }}</div>
  </div>
  <div class="card">
    <div class="label">Primera vez</div>
    <div class="value">{{ summary.first_seen }}</div>
  </div>
  <div class="card">
    <div class="label">Última vez</div>
    <div class="value">{{ summary.last_seen }}</div>
  </div>
</div>

<div class="panel">
  <h2 class="section-title">Resumen de la IP</h2>
  <table>
    <tbody>
      <tr><th>IP</th><td class="mono">{{ ip }}</td></tr>
      <tr><th>Último hostname</th><td>{{ summary.latest_hostname }}</td></tr>
      <tr><th>Último vendor</th><td>{{ summary.latest_vendor }}</td></tr>
      <tr><th>Último role</th><td>{{ summary.latest_role }}</td></tr>
      <tr><th>Última label</th><td>{{ summary.latest_label }}</td></tr>
      <tr><th>MACs observadas</th><td>{{ summary.mac_list }}</td></tr>
    </tbody>
  </table>
</div>

<div class="panel">
  <h2 class="section-title">Apariciones de la IP</h2>
  {% if sightings %}
  <table>
    <thead>
      <tr>
        <th>Scan ID</th>
        <th>Fecha</th>
        <th>Label</th>
        <th>Subred</th>
        <th>MAC</th>
        <th>Hostname</th>
        <th>Vendor</th>
        <th>Role</th>
      </tr>
    </thead>
    <tbody>
      {% for row in sightings %}
      <tr>
        <td><a href="/scan/{{ row.scan_id }}">{{ row.scan_id }}</a></td>
        <td>{{ row.timestamp }}</td>
        <td><span class="tag">{{ row.label }}</span></td>
        <td>{{ row.subnet }}</td>
        <td><a href="/host/mac/{{ row.mac }}">{{ row.mac }}</a></td>
        <td>{{ row.hostname }}</td>
        <td>{{ row.vendor }}</td>
        <td>{{ row.role }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="muted">No hay apariciones registradas.</p>
  {% endif %}
</div>
"""


def create_app(db_path: str) -> Flask:
    app = Flask(__name__)

    def get_conn():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def sort_ips(ips: List[str]) -> List[str]:
        return sorted(ips, key=lambda x: tuple(map(int, x.split("."))))

    def index_hosts_by_ip(hosts: List[Dict]) -> Dict[str, Dict]:
        return {h["ip"]: h for h in hosts}

    def diff_scans(old_hosts: List[Dict], new_hosts: List[Dict]) -> Dict[str, List[Dict]]:
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
                changed.append({
                    "ip": ip,
                    "old_mac": old_host.get("mac", "-"),
                    "new_mac": new_host.get("mac", "-"),
                    "old_hostname": old_host.get("hostname", "-"),
                    "new_hostname": new_host.get("hostname", "-"),
                })

        return {"added": added, "removed": removed, "changed": changed}

    def get_scan(scan_id: int):
        conn = get_conn()
        row = conn.execute("""
            SELECT id, timestamp, interface, subnet, self_ip, gateway_ip, host_count, label
            FROM scans
            WHERE id = ?
        """, (scan_id,)).fetchone()
        conn.close()
        return row

    def get_scan_hosts(scan_id: int) -> List[Dict]:
        conn = get_conn()
        rows = conn.execute("""
            SELECT ip, mac, hostname, vendor, role
            FROM hosts
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()
        conn.close()

        hosts = [dict(r) for r in rows]
        return sorted(hosts, key=lambda x: tuple(map(int, x["ip"].split("."))))

    def get_scan_payload(scan_id: int) -> Dict:
        scan = get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} no existe")

        hosts = get_scan_hosts(scan_id)
        return {
            "scan_info": {
                "id": scan["id"],
                "timestamp": scan["timestamp"],
                "interface": scan["interface"],
                "subnet": scan["subnet"],
                "self_ip": scan["self_ip"],
                "gateway_ip": scan["gateway_ip"],
                "host_count": scan["host_count"],
                "label": scan["label"],
            },
            "hosts": hosts,
        }

    def get_labels() -> List[str]:
        conn = get_conn()
        rows = conn.execute("""
            SELECT DISTINCT label
            FROM scans
            WHERE label IS NOT NULL AND label != '' AND label != '-'
            ORDER BY label ASC
        """).fetchall()
        conn.close()
        return [r["label"] for r in rows]

    def get_chart_data(limit: int = 30):
        conn = get_conn()
        rows = conn.execute("""
            SELECT id, timestamp, host_count
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()

        rows = list(reversed(rows))
        labels = [f'{r["id"]} · {r["timestamp"][:16]}' for r in rows]
        values = [r["host_count"] for r in rows]
        return labels, values

    def get_recent_changes(limit: int = 10):
        conn = get_conn()
        scan_rows = conn.execute("""
            SELECT id, timestamp
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit + 1,)).fetchall()
        conn.close()

        scans = list(reversed(scan_rows))
        if len(scans) < 2:
            return []

        changes = []
        for i in range(len(scans) - 1):
            s1 = scans[i]
            s2 = scans[i + 1]
            hosts1 = get_scan_hosts(s1["id"])
            hosts2 = get_scan_hosts(s2["id"])
            diff = diff_scans(hosts1, hosts2)
            changes.append({
                "scan1_id": s1["id"],
                "scan2_id": s2["id"],
                "timestamp": s2["timestamp"],
                "added": len(diff["added"]),
                "removed": len(diff["removed"]),
                "changed": len(diff["changed"]),
            })

        changes.reverse()
        return changes[:limit]

    def get_inventory(page: int, limit: int, current_label: str, current_q: str):
        offset = (page - 1) * limit

        base_query = """
            FROM hosts h
            JOIN scans s ON s.id = h.scan_id
            WHERE 1=1
        """
        params: List = []

        if current_label:
            base_query += " AND s.label = ?"
            params.append(current_label)

        if current_q:
            like = f"%{current_q}%"
            base_query += """
                AND (
                    h.mac LIKE ?
                    OR h.ip LIKE ?
                    OR h.hostname LIKE ?
                    OR h.vendor LIKE ?
                    OR h.role LIKE ?
                    OR s.label LIKE ?
                )
            """
            params.extend([like, like, like, like, like, like])

        conn = get_conn()

        total_inventory = conn.execute(
            "SELECT COUNT(DISTINCT h.mac) AS c " + base_query,
            params
        ).fetchone()["c"]

        rows = conn.execute(
            """
            SELECT
                h.mac AS mac,
                COUNT(*) AS sightings,
                COUNT(DISTINCT h.ip) AS distinct_ips,
                MIN(s.timestamp) AS first_seen,
                MAX(s.timestamp) AS last_seen,
                (
                    SELECT h2.hostname
                    FROM hosts h2
                    JOIN scans s2 ON s2.id = h2.scan_id
                    WHERE h2.mac = h.mac
                    ORDER BY s2.id DESC
                    LIMIT 1
                ) AS latest_hostname,
                (
                    SELECT h2.vendor
                    FROM hosts h2
                    JOIN scans s2 ON s2.id = h2.scan_id
                    WHERE h2.mac = h.mac
                    ORDER BY s2.id DESC
                    LIMIT 1
                ) AS latest_vendor,
                (
                    SELECT h2.role
                    FROM hosts h2
                    JOIN scans s2 ON s2.id = h2.scan_id
                    WHERE h2.mac = h.mac
                    ORDER BY s2.id DESC
                    LIMIT 1
                ) AS latest_role,
                (
                    SELECT s2.label
                    FROM hosts h2
                    JOIN scans s2 ON s2.id = h2.scan_id
                    WHERE h2.mac = h.mac
                    ORDER BY s2.id DESC
                    LIMIT 1
                ) AS latest_label
            """
            + base_query +
            """
            GROUP BY h.mac
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset]
        ).fetchall()

        conn.close()
        return rows, total_inventory

    def get_mac_history(mac: str):
        conn = get_conn()
        rows = conn.execute("""
            SELECT
                h.scan_id AS scan_id,
                s.timestamp AS timestamp,
                s.label AS label,
                s.subnet AS subnet,
                h.ip AS ip,
                h.mac AS mac,
                h.hostname AS hostname,
                h.vendor AS vendor,
                h.role AS role
            FROM hosts h
            JOIN scans s ON s.id = h.scan_id
            WHERE h.mac = ?
            ORDER BY s.id DESC
        """, (mac,)).fetchall()
        conn.close()

        sightings = [dict(r) for r in rows]
        if not sightings:
            return None, []

        ip_list = sorted({r["ip"] for r in sightings}, key=lambda x: tuple(map(int, x.split("."))))
        summary = {
            "sightings": len(sightings),
            "distinct_ips": len(ip_list),
            "first_seen": sightings[-1]["timestamp"],
            "last_seen": sightings[0]["timestamp"],
            "latest_hostname": sightings[0]["hostname"],
            "latest_vendor": sightings[0]["vendor"],
            "latest_role": sightings[0]["role"],
            "latest_label": sightings[0]["label"],
            "ip_list": ", ".join(ip_list),
        }
        return summary, sightings

    def get_ip_history(ip: str):
        conn = get_conn()
        rows = conn.execute("""
            SELECT
                h.scan_id AS scan_id,
                s.timestamp AS timestamp,
                s.label AS label,
                s.subnet AS subnet,
                h.ip AS ip,
                h.mac AS mac,
                h.hostname AS hostname,
                h.vendor AS vendor,
                h.role AS role
            FROM hosts h
            JOIN scans s ON s.id = h.scan_id
            WHERE h.ip = ?
            ORDER BY s.id DESC
        """, (ip,)).fetchall()
        conn.close()

        sightings = [dict(r) for r in rows]
        if not sightings:
            return None, []

        mac_list = sorted({r["mac"] for r in sightings})
        summary = {
            "sightings": len(sightings),
            "distinct_macs": len(mac_list),
            "first_seen": sightings[-1]["timestamp"],
            "last_seen": sightings[0]["timestamp"],
            "latest_hostname": sightings[0]["hostname"],
            "latest_vendor": sightings[0]["vendor"],
            "latest_role": sightings[0]["role"],
            "latest_label": sightings[0]["label"],
            "mac_list": ", ".join(mac_list),
        }
        return summary, sightings

    @app.route("/")
    def index():
        page = max(request.args.get("page", 1, type=int), 1)
        limit = request.args.get("limit", 20, type=int)
        if limit not in (10, 20, 50, 100):
            limit = 20

        current_label = (request.args.get("label") or "").strip()
        current_q = (request.args.get("q") or "").strip()
        offset = (page - 1) * limit

        base_query = """
            FROM scans s
            WHERE 1=1
        """
        params: List = []

        if current_label:
            base_query += " AND s.label = ?"
            params.append(current_label)

        if current_q:
            like = f"%{current_q}%"
            base_query += """
                AND (
                    CAST(s.id AS TEXT) LIKE ?
                    OR s.timestamp LIKE ?
                    OR s.interface LIKE ?
                    OR s.subnet LIKE ?
                    OR s.self_ip LIKE ?
                    OR s.gateway_ip LIKE ?
                    OR s.label LIKE ?
                    OR EXISTS (
                        SELECT 1
                        FROM hosts h
                        WHERE h.scan_id = s.id
                          AND (
                              h.ip LIKE ?
                              OR h.mac LIKE ?
                              OR h.hostname LIKE ?
                              OR h.vendor LIKE ?
                              OR h.role LIKE ?
                          )
                    )
                )
            """
            params.extend([like, like, like, like, like, like, like, like, like, like, like, like])

        conn = get_conn()

        total_filtered = conn.execute(
            "SELECT COUNT(*) AS c " + base_query,
            params
        ).fetchone()["c"]

        scans = conn.execute(
            """
            SELECT s.id, s.timestamp, s.interface, s.subnet, s.self_ip, s.gateway_ip, s.host_count, s.label
            """
            + base_query +
            """
            ORDER BY s.id DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset]
        ).fetchall()

        total_scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        total_hosts = conn.execute("SELECT COUNT(*) AS c FROM hosts").fetchone()["c"]
        total_distinct_macs = conn.execute("SELECT COUNT(DISTINCT mac) AS c FROM hosts").fetchone()["c"]
        latest = conn.execute("SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()

        labels = get_labels()
        chart_labels, chart_values = get_chart_data(30)
        recent_changes = get_recent_changes(10)

        body = render_template_string(
            INDEX_BODY,
            scans=scans,
            total_scans=total_scans,
            total_hosts=total_hosts,
            total_distinct_macs=total_distinct_macs,
            latest_scan_timestamp=latest["timestamp"] if latest else None,
            db_path=db_path,
            labels=labels,
            current_label=current_label,
            current_q=current_q,
            page=page,
            limit=limit,
            has_next=(offset + limit) < total_filtered,
            chart_labels=json.dumps(chart_labels),
            chart_values=json.dumps(chart_values),
            recent_changes=recent_changes,
        )
        return render_template_string(BASE_TEMPLATE, title="Kanshi Dashboard", body=body)

    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id: int):
        scan = get_scan(scan_id)
        if not scan:
            abort(404)

        hosts = get_scan_hosts(scan_id)

        body = render_template_string(
            SCAN_BODY,
            scan=scan,
            hosts=hosts,
        )
        return render_template_string(
            BASE_TEMPLATE,
            title=f"Kanshi - Scan {scan_id}",
            body=body,
        )

    @app.route("/scan/<int:scan_id>/json")
    def scan_json(scan_id: int):
        try:
            payload = get_scan_payload(scan_id)
        except ValueError:
            abort(404)

        response = make_response(json.dumps(payload, indent=2, ensure_ascii=False))
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.json"'
        return response

    @app.route("/scan/<int:scan_id>/csv")
    def scan_csv(scan_id: int):
        scan = get_scan(scan_id)
        if not scan:
            abort(404)

        hosts = get_scan_hosts(scan_id)

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["ip", "mac", "hostname", "vendor", "role"])
        writer.writeheader()
        writer.writerows(hosts)

        response = make_response(output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.csv"'
        return response

    @app.route("/api/scan/<int:scan_id>")
    def scan_api(scan_id: int):
        try:
            payload = get_scan_payload(scan_id)
        except ValueError:
            abort(404)
        return jsonify(payload)

    @app.route("/compare")
    def compare():
        scan1 = request.args.get("scan1", type=int)
        scan2 = request.args.get("scan2", type=int)

        if not scan1 or not scan2:
            abort(400)

        scan_row_1 = get_scan(scan1)
        scan_row_2 = get_scan(scan2)

        if not scan_row_1 or not scan_row_2:
            abort(404)

        hosts1 = get_scan_hosts(scan1)
        hosts2 = get_scan_hosts(scan2)

        diff = diff_scans(hosts1, hosts2)

        body = render_template_string(
            COMPARE_BODY,
            scan1=scan_row_1,
            scan2=scan_row_2,
            diff=diff,
        )
        return render_template_string(
            BASE_TEMPLATE,
            title=f"Kanshi - Compare {scan1} vs {scan2}",
            body=body,
        )

    @app.route("/hosts")
    def hosts_inventory():
        page = max(request.args.get("page", 1, type=int), 1)
        limit = request.args.get("limit", 20, type=int)
        if limit not in (10, 20, 50, 100):
            limit = 20

        current_label = (request.args.get("label") or "").strip()
        current_q = (request.args.get("q") or "").strip()

        items, total_inventory = get_inventory(page, limit, current_label, current_q)
        labels = get_labels()

        body = render_template_string(
            HOSTS_BODY,
            items=items,
            total_inventory=total_inventory,
            labels=labels,
            current_label=current_label,
            current_q=current_q,
            page=page,
            limit=limit,
            has_next=((page - 1) * limit + limit) < total_inventory,
        )
        return render_template_string(
            BASE_TEMPLATE,
            title="Kanshi - Inventario",
            body=body,
        )

    @app.route("/host/mac/<path:mac>")
    def host_mac_detail(mac: str):
        summary, sightings = get_mac_history(mac)
        if summary is None:
            abort(404)

        body = render_template_string(
            HOST_MAC_BODY,
            mac=mac,
            summary=summary,
            sightings=sightings,
        )
        return render_template_string(
            BASE_TEMPLATE,
            title=f"Kanshi - Host MAC {mac}",
            body=body,
        )

    @app.route("/host/ip/<path:ip>")
    def host_ip_detail(ip: str):
        summary, sightings = get_ip_history(ip)
        if summary is None:
            abort(404)

        body = render_template_string(
            HOST_IP_BODY,
            ip=ip,
            summary=summary,
            sightings=sightings,
        )
        return render_template_string(
            BASE_TEMPLATE,
            title=f"Kanshi - Host IP {ip}",
            body=body,
        )
    
    def delete_scan_by_id(scan_id: int) -> bool:
        conn = get_conn()
        cur = conn.cursor()

        exists = cur.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()["c"]

        if exists == 0:
            conn.close()
            return False

        cur.execute("DELETE FROM hosts WHERE scan_id = ?", (scan_id,))
        cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        return True
    
    @app.post("/scan/<int:scan_id>/delete")
    def scan_delete(scan_id: int):
        deleted = delete_scan_by_id(scan_id)
        if not deleted:
            abort(404)

        next_url = request.form.get("next") or url_for("index")
        return redirect(next_url)

    return app


def main():
    parser = argparse.ArgumentParser(
        description="Kanshi v9 - Dashboard web local con inventario persistente e histórico por host."
    )
    parser.add_argument("--db-path", default="kanshi.db", help="Ruta de la base de datos SQLite.")
    parser.add_argument("--host", default="127.0.0.1", help="Host donde escuchar. Por defecto: 127.0.0.1")
    parser.add_argument("--port", type=int, default=5000, help="Puerto del dashboard. Por defecto: 5000")
    parser.add_argument("--debug", action="store_true", help="Activar modo debug de Flask.")
    args = parser.parse_args()

    app = create_app(args.db_path)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()