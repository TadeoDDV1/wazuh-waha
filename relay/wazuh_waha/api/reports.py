"""
Router de reportes descargables (PDF).

Endpoints:
  GET /api/v1/reports/agent/{agent_id} — Reporte PDF de actividad por agente
"""

import io
import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from .deps import verify_api_key

router = APIRouter(tags=["reports"])


def _fmt(value: Any, default: str = "-") -> str:
    """Formatea un valor de forma segura para PDF (evita None/empty)."""
    if value is None or value == "" or value == 0:
        return default
    return str(value)


def _fmt_bytes_mb(value: Any) -> str:
    try:
        return f"{float(value):.1f} MB"
    except (TypeError, ValueError):
        return "-"


def _build_pdf(profile: dict[str, Any]) -> bytes:
    """Genera un PDF del perfil completo del agente con reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_CENTER,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=14,
        spaceAfter=6,
        borderPadding=(2, 0, 2, 0),
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
    )
    cell_style = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
    )
    cell_header_style = ParagraphStyle(
        "CellHeader",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.white,
        fontName="Helvetica-Bold",
    )

    story: list[Any] = []

    # ── Encabezado ──
    agent_name = profile.get("name", "Agente")
    agent_id = profile.get("agent_id", "?")
    ts = profile.get("timestamp", time.time())
    gen_date = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph("Reporte de Actividad — SOC Wazuh-WAHA", title_style))
    story.append(Paragraph(f"Agente <b>[{agent_id}] {agent_name}</b> · Generado: {gen_date}", subtitle_style))

    # ── 1. Identificación ──
    story.append(Paragraph("1. Identificación del Agente", section_style))
    id_data = [
        [Paragraph("Campo", cell_header_style), Paragraph("Valor", cell_header_style)],
        [Paragraph("ID", cell_style), Paragraph(_fmt(agent_id), cell_style)],
        [Paragraph("Nombre", cell_style), Paragraph(_fmt(agent_name), cell_style)],
        [Paragraph("IP", cell_style), Paragraph(_fmt(profile.get("ip")), cell_style)],
        [Paragraph("Estado", cell_style), Paragraph(_fmt(profile.get("status")), cell_style)],
        [Paragraph("Versión Wazuh", cell_style), Paragraph(_fmt(profile.get("version")), cell_style)],
        [Paragraph("Último keep-alive", cell_style), Paragraph(_fmt(profile.get("last_keep_alive")), cell_style)],
    ]
    t = Table(id_data, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0369a1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # ── 2. Hardware ──
    hw = profile.get("hardware") or {}
    story.append(Paragraph("2. Hardware", section_style))
    hw_data = [
        [Paragraph("Campo", cell_header_style), Paragraph("Valor", cell_header_style)],
        [Paragraph("CPU", cell_style), Paragraph(_fmt(hw.get("cpu_name")), cell_style)],
        [Paragraph("Núcleos", cell_style), Paragraph(_fmt(hw.get("cpu_cores")), cell_style)],
        [Paragraph("Frecuencia", cell_style), Paragraph(f"{_fmt(hw.get('cpu_mhz'))} MHz", cell_style)],
        [Paragraph("RAM Total", cell_style), Paragraph(_fmt_bytes_mb(hw.get("ram_total_mb")), cell_style)],
        [Paragraph("RAM Usada", cell_style), Paragraph(f"{_fmt_bytes_mb(hw.get('ram_used_mb'))} ({_fmt(hw.get('ram_usage_percent'))}%)", cell_style)],
        [Paragraph("RAM Libre", cell_style), Paragraph(_fmt_bytes_mb(hw.get("ram_free_mb")), cell_style)],
        [Paragraph("Board Serial", cell_style), Paragraph(_fmt(hw.get("board_serial")), cell_style)],
    ]
    t = Table(hw_data, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0284c7")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f9ff")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # ── 3. Sistema Operativo ──
    os_info = profile.get("os") or {}
    story.append(Paragraph("3. Sistema Operativo", section_style))
    os_data = [
        [Paragraph("Campo", cell_header_style), Paragraph("Valor", cell_header_style)],
        [Paragraph("Nombre", cell_style), Paragraph(_fmt(os_info.get("name")), cell_style)],
        [Paragraph("Plataforma", cell_style), Paragraph(_fmt(os_info.get("platform")), cell_style)],
        [Paragraph("Versión", cell_style), Paragraph(_fmt(os_info.get("version")), cell_style)],
        [Paragraph("Kernel", cell_style), Paragraph(_fmt(os_info.get("kernel")), cell_style)],
        [Paragraph("Arquitectura", cell_style), Paragraph(_fmt(os_info.get("architecture")), cell_style)],
        [Paragraph("Hostname", cell_style), Paragraph(_fmt(os_info.get("hostname")), cell_style)],
    ]
    t = Table(os_data, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#059669")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0fdf4")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # ── 4. Red ──
    net = profile.get("network") or {}
    ifaces = net.get("interfaces") or []
    story.append(Paragraph(f"4. Red — Interfaces ({len(ifaces)})", section_style))
    story.append(Paragraph(
        f"Tráfico total: <b>{_fmt_bytes_mb(net.get('total_rx_mb'))} recibidos</b> · "
        f"<b>{_fmt_bytes_mb(net.get('total_tx_mb'))} enviados</b>",
        body_style,
    ))
    story.append(Spacer(1, 4))
    if ifaces:
        iface_header = [
            Paragraph("Interfaz", cell_header_style),
            Paragraph("Estado", cell_header_style),
            Paragraph("IPv4", cell_header_style),
            Paragraph("MAC", cell_header_style),
            Paragraph("MTU", cell_header_style),
            Paragraph("RX (MB)", cell_header_style),
            Paragraph("TX (MB)", cell_header_style),
        ]
        iface_rows = [iface_header]
        for iface in ifaces[:15]:
            rx_mb = round((iface.get("rx_bytes") or 0) / 1048576, 1)
            tx_mb = round((iface.get("tx_bytes") or 0) / 1048576, 1)
            iface_rows.append([
                Paragraph(_fmt(iface.get("name")), cell_style),
                Paragraph(_fmt(iface.get("state")), cell_style),
                Paragraph(_fmt(iface.get("ipv4")), cell_style),
                Paragraph(_fmt(iface.get("mac")), cell_style),
                Paragraph(_fmt(iface.get("mtu")), cell_style),
                Paragraph(str(rx_mb), cell_style),
                Paragraph(str(tx_mb), cell_style),
            ])
        t = Table(iface_rows, colWidths=[22 * mm, 16 * mm, 28 * mm, 30 * mm, 14 * mm, 22 * mm, 22 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0891b2")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecfeff")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Sin interfaces registradas.", body_style))

    # ── 5. Sitios / Destinos Activos ──
    sites = profile.get("active_sites") or []
    story.append(Paragraph(f"5. Destinos de Red Activos ({len(sites)})", section_style))
    if sites:
        site_header = [
            Paragraph("Sitio", cell_header_style),
            Paragraph("Dominio", cell_header_style),
            Paragraph("IP Remota", cell_header_style),
            Paragraph("Puerto", cell_header_style),
            Paragraph("Proceso", cell_header_style),
            Paragraph("Categoría", cell_header_style),
        ]
        site_rows = [site_header]
        for site in sites[:25]:
            site_rows.append([
                Paragraph(_fmt(site.get("site_name")), cell_style),
                Paragraph(_fmt(site.get("domain")), cell_style),
                Paragraph(_fmt(site.get("remote_ip")), cell_style),
                Paragraph(_fmt(site.get("remote_port")), cell_style),
                Paragraph(_fmt(site.get("process")), cell_style),
                Paragraph(_fmt(site.get("category_label")), cell_style),
            ])
        t = Table(site_rows, colWidths=[32 * mm, 32 * mm, 28 * mm, 14 * mm, 22 * mm, 32 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0284c7")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f9ff")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Sin destinos de red registrados.", body_style))

    # ── 6. Procesos ──
    procs = (profile.get("processes") or {}).get("top_processes") or []
    total_procs = (profile.get("processes") or {}).get("total_count", len(procs))
    story.append(Paragraph(f"6. Procesos Activos ({total_procs} detectados)", section_style))
    if procs:
        proc_header = [
            Paragraph("PID", cell_header_style),
            Paragraph("Nombre", cell_header_style),
            Paragraph("Usuario", cell_header_style),
            Paragraph("Estado", cell_header_style),
        ]
        proc_rows = [proc_header]
        for proc in procs[:25]:
            proc_rows.append([
                Paragraph(_fmt(proc.get("pid")), cell_style),
                Paragraph(_fmt(proc.get("name")), cell_style),
                Paragraph(_fmt(proc.get("euser")), cell_style),
                Paragraph(_fmt(proc.get("state")), cell_style),
            ])
        t = Table(proc_rows, colWidths=[20 * mm, 60 * mm, 40 * mm, 30 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#059669")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0fdf4")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Sin procesos registrados.", body_style))

    # ── 7. Software Instalado ──
    sw = profile.get("software") or {}
    pkgs = sw.get("sample_packages") or []
    total_pkgs = sw.get("total_packages", len(pkgs))
    story.append(Paragraph(f"7. Software Instalado ({total_pkgs} paquetes)", section_style))
    if pkgs:
        pkg_header = [
            Paragraph("Paquete", cell_header_style),
            Paragraph("Versión", cell_header_style),
            Paragraph("Vendor", cell_header_style),
        ]
        pkg_rows = [pkg_header]
        for pkg in pkgs[:20]:
            pkg_rows.append([
                Paragraph(_fmt(pkg.get("name")), cell_style),
                Paragraph(_fmt(pkg.get("version")), cell_style),
                Paragraph(_fmt(pkg.get("vendor")), cell_style),
            ])
        t = Table(pkg_rows, colWidths=[60 * mm, 40 * mm, 50 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ea580c")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff7ed")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Sin paquetes registrados.", body_style))

    # ── 8. SCA CIS Benchmark ──
    sca = profile.get("sca") or {}
    story.append(Paragraph(f"8. Seguridad de Configuración (SCA) — {_fmt(sca.get('name'), 'CIS Benchmark')}", section_style))
    sca_summary = (
        f"Score: <b>{_fmt(sca.get('score'))}%</b> · "
        f"Aprobados: <b>{_fmt(sca.get('pass'))}</b> · "
        f"Fallidos: <b>{_fmt(sca.get('fail'))}</b> · "
        f"Total controles: <b>{_fmt(sca.get('total_checks'))}</b>"
    )
    story.append(Paragraph(sca_summary, body_style))
    failed_checks = sca.get("failed_checks") or []
    if failed_checks:
        story.append(Spacer(1, 4))
        story.append(Paragraph("Controles fallidos:", body_style))
        for chk in failed_checks[:10]:
            story.append(Paragraph(
                f"• <b>#{_fmt(chk.get('id'))}</b> — {_fmt(chk.get('title'))}<br/>"
                f"  <font color='#64748b'>Razón: {_fmt(chk.get('rationale'))}</font><br/>"
                f"  <font color='#059669'>Fix: {_fmt(chk.get('remediation'))}</font>",
                body_style,
            ))

    # ── 9. FIM Syscheck ──
    fim = profile.get("fim") or {}
    fim_files = fim.get("recent_files") or []
    story.append(Paragraph(f"9. Integridad de Archivos (FIM) — {_fmt(fim.get('total_monitored'))} monitoreados", section_style))
    if fim_files:
        fim_header = [
            Paragraph("Archivo", cell_header_style),
            Paragraph("Tamaño", cell_header_style),
            Paragraph("Permisos", cell_header_style),
            Paragraph("MD5", cell_header_style),
        ]
        fim_rows = [fim_header]
        for f in fim_files[:15]:
            md5 = _fmt(f.get("md5"))
            if md5 != "-" and len(md5) > 12:
                md5 = md5[:12] + "…"
            fim_rows.append([
                Paragraph(_fmt(f.get("file")), cell_style),
                Paragraph(_fmt(f.get("size")), cell_style),
                Paragraph(_fmt(f.get("perm")), cell_style),
                Paragraph(md5, cell_style),
            ])
        t = Table(fim_rows, colWidths=[75 * mm, 22 * mm, 22 * mm, 30 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c3aed")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f3ff")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Sin cambios recientes registrados por Syscheck.", body_style))

    # ── 10. Detecciones Wazuh ──
    detections = profile.get("recent_detections") or []
    story.append(Paragraph(f"10. Detecciones de Seguridad Wazuh ({len(detections)} alertas)", section_style))
    if detections:
        det_header = [
            Paragraph("Nivel", cell_header_style),
            Paragraph("Regla", cell_header_style),
            Paragraph("Descripción", cell_header_style),
            Paragraph("Origen", cell_header_style),
            Paragraph("Timestamp", cell_header_style),
        ]
        det_rows = [det_header]
        for det in detections[:20]:
            det_rows.append([
                Paragraph(_fmt(det.get("level_es"), _fmt(det.get("level"))), cell_style),
                Paragraph(_fmt(det.get("rule_id")), cell_style),
                Paragraph(_fmt(det.get("description")), cell_style),
                Paragraph(_fmt(det.get("srcip")), cell_style),
                Paragraph(_fmt(det.get("timestamp")), cell_style),
            ])
        t = Table(det_rows, colWidths=[22 * mm, 16 * mm, 68 * mm, 24 * mm, 28 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dc2626")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fef2f2")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Sin detecciones de seguridad recientes.", body_style))

    # ── Pie ──
    story.append(Spacer(1, 16))
    story.append(Paragraph(
        f"<font color='#94a3b8' size='8'>Generado por wazuh-waha · {gen_date} · Agente [{agent_id}] {agent_name}</font>",
        ParagraphStyle("Footer", parent=body_style, alignment=TA_CENTER),
    ))

    doc.build(story)
    return buf.getvalue()


@router.get("/api/v1/reports/agent/{agent_id}")
async def download_agent_report(
    agent_id: str,
    _: None = Depends(verify_api_key),
) -> Response:
    """Genera y devuelve un PDF con la ficha forense completa del agente."""
    from .telemetry import _fetch_agent_full_profile

    profile = await _fetch_agent_full_profile(agent_id)
    pdf_bytes = _build_pdf(profile)

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reporte_agente_{agent_id}_{now}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
