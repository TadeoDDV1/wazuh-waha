"""
Router de reportes descargables (PDF).

Genera informes forenses ejecutivos y técnicos por agente con reportlab,
incluyendo ficha de identidad, inventario de hardware/SO, interfaces de red,
destinos activos, procesos, software, evaluación CIS (SCA), integridad FIM
y detecciones de seguridad correlacionadas.

Endpoints:
  GET /api/v1/reports/agent/{agent_id} — Reporte PDF de actividad y postura forense
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
    """Formatea bytes numéricos a megabytes con un decimal."""
    try:
        val = float(value)
        return f"{val:.1f} MB"
    except (TypeError, ValueError):
        return "-"


def _build_pdf(profile: dict[str, Any]) -> bytes:
    """
    Genera un PDF con diseño forense profesional y explicaciones detalladas
    para cada uno de los 10 apartados del perfil de seguridad del agente.
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    class NumberedCanvas(canvas.Canvas):
        """Canvas de dos pasos para numeración dinámica y pie institucional en cada página."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._saved_page_states: list[dict[str, Any]] = []

        def showPage(self) -> None:
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_page_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_page_decorations(self, page_count: int) -> None:
            self.saveState()
            # Encabezado secundario superior (en páginas > 1)
            if self._pageNumber > 1:
                self.setFont("Helvetica-Bold", 7)
                self.setFillColor(colors.HexColor("#0f172a"))
                self.drawString(16 * mm, 297 * mm - 11 * mm, "WAZUH-WAHA SOC")
                self.setFont("Helvetica", 7)
                self.setFillColor(colors.HexColor("#64748b"))
                self.drawString(42 * mm, 297 * mm - 11 * mm, "· Informe Forense y Auditoría de Seguridad de Endpoint")
                self.drawRightString(210 * mm - 16 * mm, 297 * mm - 11 * mm, f"Agente [{agent_id}] {agent_name}")
                self.setStrokeColor(colors.HexColor("#e2e8f0"))
                self.setLineWidth(0.5)
                self.line(16 * mm, 297 * mm - 13 * mm, 210 * mm - 16 * mm, 297 * mm - 13 * mm)

            # Pie institucional
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(16 * mm, 14 * mm, 210 * mm - 16 * mm, 14 * mm)

            self.setFont("Helvetica-Bold", 7)
            self.setFillColor(colors.HexColor("#dc2626"))
            self.drawString(16 * mm, 9.5 * mm, "CONFIDENCIAL")

            self.setFont("Helvetica", 7)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(38 * mm, 9.5 * mm, "· Generado por Wazuh-WAHA SOC Suite · Uso exclusivo del equipo de seguridad")

            page_str = f"Página {self._pageNumber} de {page_count}"
            self.drawRightString(210 * mm - 16 * mm, 9.5 * mm, page_str)
            self.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()

    # ── Tipografías y Estilos ──
    doc_title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Title"],
        fontSize=15,
        leading=18,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        alignment=TA_LEFT,
    )
    doc_subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_LEFT,
    )
    meta_label_style = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_RIGHT,
    )
    meta_val_style = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=10,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        alignment=TA_RIGHT,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=4,
    )
    callout_style = ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#334155"),
        alignment=TA_JUSTIFY,
    )
    empty_style = ParagraphStyle(
        "EmptyText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#047857"),
        alignment=TA_LEFT,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
        alignment=TA_LEFT,
    )
    cell_style = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#1e293b"),
    )
    cell_bold_style = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
    )
    cell_header_style = ParagraphStyle(
        "CellHeader",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
        fontName="Helvetica-Bold",
    )
    kpi_number_style = ParagraphStyle(
        "KpiNumber",
        parent=styles["Normal"],
        fontSize=13,
        leading=15,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    kpi_label_style = ParagraphStyle(
        "KpiLabel",
        parent=styles["Normal"],
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor("#64748b"),
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    kpi_sub_style = ParagraphStyle(
        "KpiSub",
        parent=styles["Normal"],
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_CENTER,
    )

    story: list[Any] = []

    # ── Metadatos del Agente ──
    agent_name = profile.get("name") or profile.get("agent_name") or "Agente"
    agent_id = str(profile.get("agent_id", "?"))
    status_raw = str(profile.get("status", "unknown")).lower()
    ts = profile.get("timestamp", time.time())
    gen_date = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    is_active = status_raw in ("active", "activo", "online")
    status_color = "#10b981" if is_active else "#ef4444"
    status_badge = f"<font color='{status_color}'>●</font> {status_raw.upper()}"

    # ── Helper para crear cuadros explicativos por apartado ──
    def _add_section_callout(
        objective: str,
        relevance: str,
        interpretation: str,
    ) -> None:
        text = (
            f"<b>🎯 Objetivo de Auditoría:</b> {objective}<br/>"
            f"<b>🛡️ Relevancia para la Seguridad:</b> {relevance}<br/>"
            f"<b>💡 Criterio de Análisis:</b> {interpretation}"
        )
        p = Paragraph(text, callout_style)
        t_box = Table([[p]], colWidths=[178 * mm])
        t_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("LINEBEFORE", (0, 0), (0, -1), 3.0, colors.HexColor("#0284c7")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(t_box)
        story.append(Spacer(1, 3 * mm))

    # ── Helper para estados normales / vacíos ──
    def _add_empty_state(message: str) -> None:
        p = Paragraph(f"<b>✓ Estado Normal / Sin Registros Anómalos:</b> {message}", empty_style)
        t_empty = Table([[p]], colWidths=[178 * mm])
        t_empty.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbf7d0")),
            ("LINEBEFORE", (0, 0), (0, -1), 3.0, colors.HexColor("#10b981")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(t_empty)
        story.append(Spacer(1, 3 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # ENCABEZADO EJECUTIVO (BANNER SOC)
    # ══════════════════════════════════════════════════════════════════════════
    header_left = [
        Paragraph("INFORME FORENSE Y AUDITORÍA DE SEGURIDAD", doc_title_style),
        Spacer(1, 1 * mm),
        Paragraph("SOC Wazuh-WAHA · Ficha Integral de Monitoreo de Endpoint", doc_subtitle_style),
    ]
    header_right = [
        Paragraph(f"AGENTE [{agent_id}] <b>{agent_name}</b>", meta_val_style),
        Paragraph(f"ESTADO: {status_badge}", meta_val_style),
        Paragraph(f"Emisión: {gen_date}", meta_label_style),
    ]
    header_table = Table([[header_left, header_right]], colWidths=[112 * mm, 66 * mm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 2.5, colors.HexColor("#0284c7")),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # RESUMEN EJECUTIVO / TARJETAS KPI DE POSTURA
    # ══════════════════════════════════════════════════════════════════════════
    sca = profile.get("sca") or {}
    sca_score = sca.get("score")
    sca_score_str = f"{sca_score}%" if sca_score is not None else "N/A"
    if isinstance(sca_score, (int, float)):
        sca_color = "#10b981" if sca_score >= 80 else ("#f59e0b" if sca_score >= 60 else "#ef4444")
    else:
        sca_color = "#64748b"

    detections = profile.get("recent_detections") or []
    crit_count = sum(1 for d in detections if int(d.get("level") or 0) >= 12)
    high_count = sum(1 for d in detections if 8 <= int(d.get("level") or 0) < 12)

    sites = profile.get("active_sites") or []
    fim = profile.get("fim") or {}
    fim_count = fim.get("total_monitored", len(fim.get("recent_files") or []))

    kpi_card_1 = [
        Paragraph(f"<font color='{status_color}'>●</font> {status_raw.upper()}", kpi_number_style),
        Paragraph("ESTADO DE ENLACE", kpi_label_style),
        Paragraph(_fmt(profile.get("ip"), "Sin IP"), kpi_sub_style),
    ]
    kpi_card_2 = [
        Paragraph(f"<font color='{sca_color}'>{sca_score_str}</font>", kpi_number_style),
        Paragraph("CUMPLIMIENTO CIS SCA", kpi_label_style),
        Paragraph(f"Pasa: {sca.get('pass', 0)} · Falla: {sca.get('fail', 0)}", kpi_sub_style),
    ]
    kpi_card_3 = [
        Paragraph(
            f"<font color='{'#ef4444' if crit_count > 0 else ('#f59e0b' if high_count > 0 else '#10b981')}'>{len(detections)}</font>",
            kpi_number_style,
        ),
        Paragraph("ALERTAS DETECTADAS", kpi_label_style),
        Paragraph(f"Críticas: {crit_count} · Altas: {high_count}", kpi_sub_style),
    ]
    kpi_card_4 = [
        Paragraph(f"{len(sites)} / {fim_count}", kpi_number_style),
        Paragraph("DESTINOS / ARCHIVOS FIM", kpi_label_style),
        Paragraph("Sockets activos y monitoreo", kpi_sub_style),
    ]

    kpi_table = Table([[kpi_card_1, kpi_card_2, kpi_card_3, kpi_card_4]], colWidths=[44.5 * mm] * 4)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 5 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 1. IDENTIFICACIÓN Y REGISTRO DEL AGENTE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("1. Identificación y Registro del Agente", section_style))
    _add_section_callout(
        objective="Verificar la identidad del endpoint, versión del software Wazuh, IP reportada y la sincronización del canal seguro con el clúster Manager.",
        relevance="Un keep-alive atrasado o un estado desconectado indica pérdida de visibilidad en el endpoint, posible caída del daemon local o bloqueo en la red.",
        interpretation="El estado debe ser ACTIVO con un último keep-alive reciente. La versión del agente debe mantenerse homologada con el Wazuh Manager (v4.9+).",
    )
    id_data = [
        [Paragraph("Campo de Control", cell_header_style), Paragraph("Valor Registrado", cell_header_style), Paragraph("Parámetro Técnico", cell_header_style)],
        [Paragraph("Identificador Único (ID)", cell_bold_style), Paragraph(_fmt(agent_id), cell_style), Paragraph("ID secuencial en base de datos Wazuh", cell_style)],
        [Paragraph("Nombre de Host (Hostname)", cell_bold_style), Paragraph(_fmt(agent_name), cell_style), Paragraph("FQDN / Nombre NetBIOS del endpoint", cell_style)],
        [Paragraph("Dirección IP de Enlace", cell_bold_style), Paragraph(_fmt(profile.get("ip")), cell_style), Paragraph("IP pública o privada desde donde conecta", cell_style)],
        [Paragraph("Estado Operativo", cell_bold_style), Paragraph(status_badge, cell_style), Paragraph("Enlace continuo de heartbeat", cell_style)],
        [Paragraph("Versión del Agente", cell_bold_style), Paragraph(_fmt(profile.get("version")), cell_style), Paragraph("Binario instalado de wazuh-agent", cell_style)],
        [Paragraph("Último Keep-Alive", cell_bold_style), Paragraph(_fmt(profile.get("last_keep_alive")), cell_style), Paragraph("Sincronización más reciente de telemetría", cell_style)],
    ]
    t_id = Table(id_data, colWidths=[45 * mm, 60 * mm, 73 * mm])
    t_id.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_id)
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 2. CAPACIDAD Y CONSUMO DE HARDWARE
    # ══════════════════════════════════════════════════════════════════════════
    hw = profile.get("hardware") or {}
    story.append(Paragraph("2. Capacidad y Consumo de Hardware", section_style))
    _add_section_callout(
        objective="Auditar las especificaciones de hardware del host, volumen de memoria RAM asignada/utilizada e identificadores de placa madre.",
        relevance="Permite detectar agotamiento de memoria, degradación por DoS, actividades intensivas no autorizadas (como minería de criptoactivos) y validar seriales físicos para control de inventario.",
        interpretation="Un uso de RAM sostenido > 85% requiere investigación de procesos pesados. El número de serie de placa previene clonación o suplantación de activos.",
    )
    ram_usage = hw.get("ram_usage_percent")
    ram_color = "#ef4444" if (ram_usage and float(ram_usage) > 85) else "#1e293b"
    ram_text = f"{_fmt_bytes_mb(hw.get('ram_used_mb'))} ({_fmt(ram_usage)}%)" if ram_usage else _fmt_bytes_mb(hw.get("ram_used_mb"))

    hw_data = [
        [Paragraph("Componente", cell_header_style), Paragraph("Valor Detectado", cell_header_style), Paragraph("Detalle / Observación", cell_header_style)],
        [Paragraph("Microprocesador (CPU)", cell_bold_style), Paragraph(_fmt(hw.get("cpu_name")), cell_style), Paragraph("Modelo y arquitectura de procesamiento", cell_style)],
        [Paragraph("Núcleos Físicos / Lógicos", cell_bold_style), Paragraph(_fmt(hw.get("cpu_cores")), cell_style), Paragraph("Capacidad de hilos de ejecución", cell_style)],
        [Paragraph("Frecuencia Base", cell_bold_style), Paragraph(f"{_fmt(hw.get('cpu_mhz'))} MHz", cell_style), Paragraph("Velocidad de reloj reportada", cell_style)],
        [Paragraph("Memoria RAM Total", cell_bold_style), Paragraph(_fmt_bytes_mb(hw.get("ram_total_mb")), cell_style), Paragraph("Capacidad instalada del host", cell_style)],
        [Paragraph("Memoria RAM en Uso", cell_bold_style), Paragraph(f"<font color='{ram_color}'><b>{ram_text}</b></font>", cell_style), Paragraph("Consumo de memoria dinámico", cell_style)],
        [Paragraph("Memoria RAM Libre", cell_bold_style), Paragraph(_fmt_bytes_mb(hw.get("ram_free_mb")), cell_style), Paragraph("Margen disponible para el sistema", cell_style)],
        [Paragraph("Serial de Placa Madre", cell_bold_style), Paragraph(_fmt(hw.get("board_serial")), cell_style), Paragraph("Identificador criptográfico de hardware", cell_style)],
    ]
    t_hw = Table(hw_data, colWidths=[45 * mm, 60 * mm, 73 * mm])
    t_hw.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_hw)
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 3. SISTEMA OPERATIVO Y PLATAFORMA
    # ══════════════════════════════════════════════════════════════════════════
    os_info = profile.get("os") or {}
    story.append(Paragraph("3. Sistema Operativo y Plataforma", section_style))
    _add_section_callout(
        objective="Identificar la distribución del sistema operativo, versión exacta, arquitectura del binario y compilación del kernel en uso.",
        relevance="Determina la superficie de ataque inicial del equipo. Permite contrastar vulnerabilidades de kernel (LPE) y verificar cumplimiento del ciclo de vida de parches (EOL).",
        interpretation="Kernels antiguos o sistemas operativos sin soporte activo deben actualizarse con urgencia para evitar ejecución de exploits locales o desbordamientos.",
    )
    os_data = [
        [Paragraph("Parámetro del Sistema", cell_header_style), Paragraph("Configuración Reportada", cell_header_style), Paragraph("Implicación de Seguridad", cell_header_style)],
        [Paragraph("Nombre del Sistema Operativo", cell_bold_style), Paragraph(_fmt(os_info.get("name")), cell_style), Paragraph("Familia del SO y distribución", cell_style)],
        [Paragraph("Plataforma Base", cell_bold_style), Paragraph(_fmt(os_info.get("platform")), cell_style), Paragraph("Entorno (Linux, Windows, macOS)", cell_style)],
        [Paragraph("Versión / Release", cell_bold_style), Paragraph(_fmt(os_info.get("version")), cell_style), Paragraph("Nivel de actualización de paquetes", cell_style)],
        [Paragraph("Compilación del Kernel", cell_bold_style), Paragraph(_fmt(os_info.get("kernel")), cell_style), Paragraph("Núcleo del sistema (superficie LPE)", cell_style)],
        [Paragraph("Arquitectura del Procesador", cell_bold_style), Paragraph(_fmt(os_info.get("architecture")), cell_style), Paragraph("Set de instrucciones (x86_64, aarch64)", cell_style)],
        [Paragraph("Nombre de Nodo (Hostname)", cell_bold_style), Paragraph(_fmt(os_info.get("hostname")), cell_style), Paragraph("Identificador en red interna", cell_style)],
    ]
    t_os = Table(os_data, colWidths=[45 * mm, 60 * mm, 73 * mm])
    t_os.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_os)
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 4. INTERFACES DE RED Y TRÁFICO ACUMULADO
    # ══════════════════════════════════════════════════════════════════════════
    net = profile.get("network") or {}
    ifaces = net.get("interfaces") or []
    story.append(Paragraph(f"4. Interfaces de Red y Tráfico Acumulado ({len(ifaces)} interfaces)", section_style))
    _add_section_callout(
        objective="Mapear las tarjetas de red físicas y virtuales, sus direcciones IPv4 asignadas, MAC address física y consumo de datos acumulado (RX/TX).",
        relevance="Ayuda a descubrir adaptadores en modo promiscuo, túneles VPN no declarados, interfaces puente secundarias o volúmenes anómalos de tráfico que sugieran exfiltración.",
        interpretation="Interfaces no reconocidas o volúmenes masivos de TX hacia direcciones no corporativas deben correlacionarse con los registros del firewall perimetral.",
    )
    story.append(Paragraph(
        f"<b>Tráfico Global Acumulado del Endpoint:</b> <font color='#0284c7'><b>{_fmt_bytes_mb(net.get('total_rx_mb'))} recibidos</b></font> · "
        f"<font color='#059669'><b>{_fmt_bytes_mb(net.get('total_tx_mb'))} transmitidos</b></font>",
        body_style,
    ))
    story.append(Spacer(1, 2 * mm))

    if ifaces:
        iface_header = [
            Paragraph("Interfaz", cell_header_style),
            Paragraph("Estado", cell_header_style),
            Paragraph("IPv4 Asignada", cell_header_style),
            Paragraph("Dirección MAC", cell_header_style),
            Paragraph("MTU", cell_header_style),
            Paragraph("RX (MB)", cell_header_style),
            Paragraph("TX (MB)", cell_header_style),
        ]
        iface_rows = [iface_header]
        for iface in ifaces[:15]:
            rx_mb = round((iface.get("rx_bytes") or 0) / 1048576, 1)
            tx_mb = round((iface.get("tx_bytes") or 0) / 1048576, 1)
            state_val = str(iface.get("state", "down")).lower()
            state_color = "#10b981" if state_val == "up" else "#94a3b8"
            iface_rows.append([
                Paragraph(_fmt(iface.get("name")), cell_bold_style),
                Paragraph(f"<font color='{state_color}'><b>{state_val.upper()}</b></font>", cell_style),
                Paragraph(_fmt(iface.get("ipv4")), cell_style),
                Paragraph(_fmt(iface.get("mac")), cell_style),
                Paragraph(_fmt(iface.get("mtu")), cell_style),
                Paragraph(str(rx_mb), cell_style),
                Paragraph(str(tx_mb), cell_style),
            ])
        t_iface = Table(iface_rows, colWidths=[25 * mm, 18 * mm, 32 * mm, 35 * mm, 16 * mm, 26 * mm, 26 * mm])
        t_iface.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_iface)
    else:
        _add_empty_state("No se encontraron interfaces de red activas registradas para este agente.")
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 5. DESTINOS DE RED ACTIVOS & SOCKETS REMOTOS
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph(f"5. Destinos de Red Activos & Sockets Remotos ({len(sites)} detectados)", section_style))
    _add_section_callout(
        objective="Auditar los sockets de red establecidos por procesos locales hacia servidores y servicios externos en tiempo real.",
        relevance="Es la vía primaria para detectar actividad de Command & Control (C2), troyanos, minería de datos, balizas (beacons) o navegación indebida.",
        interpretation="Conexiones hacia puertos no estándar (ej. 4444, 8080 no corporativo, 1337) o IPs foráneas sin resolución DNS clara requieren bloqueo y aislamiento inmediato.",
    )
    if sites:
        site_header = [
            Paragraph("Servicio / Destino", cell_header_style),
            Paragraph("Dominio Web", cell_header_style),
            Paragraph("IP Remota", cell_header_style),
            Paragraph("Puerto", cell_header_style),
            Paragraph("Proceso Origen", cell_header_style),
            Paragraph("Categoría", cell_header_style),
        ]
        site_rows = [site_header]
        for site in sites[:25]:
            port_val = str(site.get("remote_port", ""))
            port_alert = "#ef4444" if port_val in ("4444", "1337", "6667", "31337") else "#0f172a"
            site_rows.append([
                Paragraph(_fmt(site.get("site_name")), cell_bold_style),
                Paragraph(_fmt(site.get("domain")), cell_style),
                Paragraph(_fmt(site.get("remote_ip")), cell_style),
                Paragraph(f"<font color='{port_alert}'><b>{_fmt(port_val)}</b></font>", cell_style),
                Paragraph(_fmt(site.get("process")), cell_style),
                Paragraph(_fmt(site.get("category_label")), cell_style),
            ])
        t_sites = Table(site_rows, colWidths=[32 * mm, 35 * mm, 30 * mm, 18 * mm, 28 * mm, 35 * mm])
        t_sites.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_sites)
    else:
        _add_empty_state("Sin conexiones externas o destinos de red activos registrados en la ventana de auditoría.")
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 6. PROCESOS EN EJECUCIÓN (TOP PROCESSES)
    # ══════════════════════════════════════════════════════════════════════════
    procs = (profile.get("processes") or {}).get("top_processes") or []
    total_procs = (profile.get("processes") or {}).get("total_count", len(procs))
    story.append(Paragraph(f"6. Procesos en Ejecución ({total_procs} detectados)", section_style))
    _add_section_callout(
        objective="Inspeccionar los procesos y servicios actualmente en ejecución en la memoria del host, su PID asociado y la cuenta de usuario ejecutora.",
        relevance="Permite identificar binarios no autorizados, scripts maliciosos ejecutándose en segundo plano, procesos con elevación indebida de privilegios y mecanismos de persistencia.",
        interpretation="Procesos corriendo como 'root' o 'SYSTEM' fuera de las rutas estándar del sistema operativo (/usr/bin, /usr/sbin, C:\\Windows\\System32) representan alertas rojas de compromiso.",
    )
    if procs:
        proc_header = [
            Paragraph("PID", cell_header_style),
            Paragraph("Nombre del Proceso / Binario", cell_header_style),
            Paragraph("Usuario Ejecutor", cell_header_style),
            Paragraph("Estado de Ejecución", cell_header_style),
        ]
        proc_rows = [proc_header]
        for proc in procs[:25]:
            user_val = str(proc.get("euser") or proc.get("user") or "-")
            user_color = "#dc2626" if user_val in ("root", "SYSTEM", "Administrator") else "#1e293b"
            proc_rows.append([
                Paragraph(_fmt(proc.get("pid")), cell_bold_style),
                Paragraph(_fmt(proc.get("name")), cell_style),
                Paragraph(f"<font color='{user_color}'><b>{user_val}</b></font>", cell_style),
                Paragraph(_fmt(proc.get("state")), cell_style),
            ])
        t_procs = Table(proc_rows, colWidths=[22 * mm, 70 * mm, 46 * mm, 40 * mm])
        t_procs.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_procs)
    else:
        _add_empty_state("Sin procesos registrados en la telemetría del agente.")
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 7. SOFTWARE INSTALADO Y PAQUETERÍA (SYSCOLLECTOR)
    # ══════════════════════════════════════════════════════════════════════════
    sw = profile.get("software") or {}
    pkgs = sw.get("sample_packages") or []
    total_pkgs = sw.get("total_packages", len(pkgs))
    story.append(Paragraph(f"7. Software Instalado y Paquetería ({total_pkgs} paquetes registrados)", section_style))
    _add_section_callout(
        objective="Generar el inventario de software, aplicaciones y paquetes desplegados en el endpoint a través del módulo Syscollector de Wazuh.",
        relevance="Base fundamental para la gestión de vulnerabilidades (SBOM), correlación continua contra la base de datos oficial de CVEs y detección de software no homologado.",
        interpretation="Paquetes con versiones antiguas o con CVEs críticas asociadas deben priorizarse para actualización o desinstalación.",
    )
    if pkgs:
        pkg_header = [
            Paragraph("Nombre del Paquete / Aplicación", cell_header_style),
            Paragraph("Versión Instalada", cell_header_style),
            Paragraph("Proveedor / Vendor", cell_header_style),
        ]
        pkg_rows = [pkg_header]
        for pkg in pkgs[:20]:
            pkg_rows.append([
                Paragraph(_fmt(pkg.get("name")), cell_bold_style),
                Paragraph(_fmt(pkg.get("version")), cell_style),
                Paragraph(_fmt(pkg.get("vendor")), cell_style),
            ])
        t_pkgs = Table(pkg_rows, colWidths=[75 * mm, 45 * mm, 58 * mm])
        t_pkgs.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_pkgs)
    else:
        _add_empty_state("Sin paquetes o software reportados por el inventario de Syscollector.")
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 8. SEGURIDAD DE CONFIGURACIÓN (SCA — CIS BENCHMARK)
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph(f"8. Seguridad de Configuración (SCA) — {_fmt(sca.get('name'), 'CIS Benchmark')}", section_style))
    _add_section_callout(
        objective="Auditar la postura de fortificación (hardening) del sistema operativo contra los estándares internacionales del Center for Internet Security (CIS Benchmark).",
        relevance="Las brechas de configuración (como permisos laxos, contraseñas débiles o servicios obsoletos activos) son los vectores más explotados por atacantes para acceder a una red.",
        interpretation="Niveles de cumplimiento: Verde (>80%: Fuerte), Amarillo (60-79%: Moderado), Rojo (<60%: Débil/Crítico). Cada control fallido detalla la justificación y la orden de remediación.",
    )
    sca_summary = (
        f"<b>Puntaje de Cumplimiento Global:</b> <font color='{sca_color}'><b>{sca_score_str}</b></font> · "
        f"<b>Aprobados:</b> <font color='#10b981'><b>{_fmt(sca.get('pass'))}</b></font> · "
        f"<b>Fallidos:</b> <font color='#ef4444'><b>{_fmt(sca.get('fail'))}</b></font> · "
        f"<b>Total Evaluados:</b> <b>{_fmt(sca.get('total_checks'))}</b>"
    )
    story.append(Paragraph(sca_summary, body_style))

    failed_checks = sca.get("failed_checks") or []
    if failed_checks:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("<b>Principales Controles Fallidos que Requieren Remediación:</b>", body_style))
        story.append(Spacer(1, 1.5 * mm))
        for chk in failed_checks[:10]:
            chk_card = [
                Paragraph(
                    f"<b>Control #{_fmt(chk.get('id'))}:</b> {_fmt(chk.get('title'))}<br/>"
                    f"<b>Riesgo Identificado:</b> <font color='#64748b'>{_fmt(chk.get('rationale'))}</font><br/>"
                    f"<b>Procedimiento de Remediación:</b> <font color='#0369a1'><code>{_fmt(chk.get('remediation'))}</code></font>",
                    callout_style,
                )
            ]
            t_chk = Table([chk_card], colWidths=[178 * mm])
            t_chk.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff7ed")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fed7aa")),
                ("LINEBEFORE", (0, 0), (0, -1), 3.0, colors.HexColor("#f97316")),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t_chk)
            story.append(Spacer(1, 2 * mm))
    else:
        story.append(Spacer(1, 2 * mm))
        _add_empty_state("No se registran controles fallidos en la evaluación CIS Benchmark analizada.")
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 9. MONITOREO DE INTEGRIDAD DE ARCHIVOS (FIM / SYSCHECK)
    # ══════════════════════════════════════════════════════════════════════════
    fim_files = fim.get("recent_files") or []
    story.append(Paragraph(f"9. Monitoreo de Integridad de Archivos (FIM) — {fim_count} archivos supervisados", section_style))
    _add_section_callout(
        objective="Rastrear cambios, modificaciones no autorizadas, alteraciones de permisos o creación/eliminación de archivos críticos del sistema mediante huellas hash MD5/SHA256.",
        relevance="La alteración de archivos de configuración (/etc/passwd, /etc/sudoers) o el reemplazo de binarios clave es el sello característico de intrusiones, rootkits o manipulación interna.",
        interpretation="Cualquier cambio detectado fuera de una ventana de mantenimiento programada debe tratarse como un Indicador de Compromiso (IoC) y someterse a análisis de forensia digital.",
    )
    if fim_files:
        fim_header = [
            Paragraph("Ruta del Archivo", cell_header_style),
            Paragraph("Tamaño", cell_header_style),
            Paragraph("Permisos", cell_header_style),
            Paragraph("Checksum MD5", cell_header_style),
        ]
        fim_rows = [fim_header]
        for f in fim_files[:15]:
            md5 = _fmt(f.get("md5"))
            if md5 != "-" and len(md5) > 16:
                md5 = md5[:16] + "…"
            fim_rows.append([
                Paragraph(_fmt(f.get("file")), cell_bold_style),
                Paragraph(_fmt(f.get("size")), cell_style),
                Paragraph(_fmt(f.get("perm")), cell_style),
                Paragraph(f"<code>{md5}</code>", cell_style),
            ])
        t_fim = Table(fim_rows, colWidths=[85 * mm, 25 * mm, 28 * mm, 40 * mm])
        t_fim.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_fim)
    else:
        _add_empty_state("Sin eventos recientes de alteración de integridad de archivos reportados por Syscheck.")
    story.append(Spacer(1, 4 * mm))

    # ══════════════════════════════════════════════════════════════════════════
    # 10. DETECCIONES Y ALERTAS RECIENTES DE SEGURIDAD (WAZUH SIEM)
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph(f"10. Detecciones y Alertas Recientes de Seguridad ({len(detections)} eventos)", section_style))
    _add_section_callout(
        objective="Consolidar las alertas e incidentes de seguridad correlacionados por los motores de reglas y firmas del Wazuh SIEM en el endpoint.",
        relevance="Provee la evidencia directa de intentos de intrusión (fuerza bruta SSH, escaneo de puertos, inyección, malware o anomalías de comportamiento).",
        interpretation="Escala de criticidad: Nivel 1-4 (Bajo / Informativo), Nivel 5-7 (Medio / Advertencia), Nivel 8-11 (Alto / Riesgo Severo), Nivel 12-15 (Crítico / Respuesta Inmediata).",
    )
    if detections:
        det_header = [
            Paragraph("Severidad", cell_header_style),
            Paragraph("Regla ID", cell_header_style),
            Paragraph("Descripción del Evento", cell_header_style),
            Paragraph("IP Origen", cell_header_style),
            Paragraph("Fecha y Hora", cell_header_style),
        ]
        det_rows = [det_header]
        for det in detections[:20]:
            lvl = int(det.get("level") or 0)
            if lvl >= 12:
                badge_color = "#dc2626"
                lvl_label = f"CRÍTICO (L{lvl})"
            elif lvl >= 8:
                badge_color = "#ea580c"
                lvl_label = f"ALTO (L{lvl})"
            elif lvl >= 5:
                badge_color = "#d97706"
                lvl_label = f"MEDIO (L{lvl})"
            else:
                badge_color = "#0284c7"
                lvl_label = f"BAJO (L{lvl})"

            det_rows.append([
                Paragraph(f"<font color='{badge_color}'><b>{lvl_label}</b></font>", cell_style),
                Paragraph(f"<b>#{_fmt(det.get('rule_id'))}</b>", cell_style),
                Paragraph(_fmt(det.get("description")), cell_style),
                Paragraph(_fmt(det.get("srcip")), cell_style),
                Paragraph(_fmt(det.get("timestamp")), cell_style),
            ])
        t_det = Table(det_rows, colWidths=[24 * mm, 20 * mm, 70 * mm, 30 * mm, 34 * mm])
        t_det.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_det)
    else:
        _add_empty_state("No se registran alertas de seguridad en el periodo analizado para este agente.")

    # ── Cierre del documento ──
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=3 * mm))
    story.append(Paragraph(
        f"<font color='#64748b' size='7.5'>Fin del informe forense oficial · Generado por Wazuh-WAHA SOC Suite · Agente [{agent_id}] {agent_name} · {gen_date}</font>",
        ParagraphStyle("DocFooter", parent=body_style, alignment=TA_CENTER),
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
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
