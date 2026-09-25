"""Create two print-ready Sentinel diagrams as a PDF and PNG pages."""
from pathlib import Path
from math import atan2, cos, sin, pi

import pypdfium2 as pdfium
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "diagrams"
OUT.mkdir(exist_ok=True)
PDF = OUT / "Sentinel_Project_Diagrams.pdf"
PAGE_W, PAGE_H = landscape(A4)

INK = colors.HexColor("#17243a")
MUTED = colors.HexColor("#55657a")
LINE = colors.HexColor("#d7e1eb")
BLUE = colors.HexColor("#2563eb")
BLUE_LIGHT = colors.HexColor("#eff6ff")
TEAL = colors.HexColor("#0f766e")
TEAL_LIGHT = colors.HexColor("#eaf8f5")
AMBER = colors.HexColor("#a65d10")
AMBER_LIGHT = colors.HexColor("#fff6e8")
GRAY_LIGHT = colors.HexColor("#f7f9fc")


def text(c, x, y, value, size=10, color=INK, font="Helvetica", align="left"):
    c.setFillColor(color)
    c.setFont(font, size)
    if align == "center":
        c.drawCentredString(x, y, value)
    elif align == "right":
        c.drawRightString(x, y, value)
    else:
        c.drawString(x, y, value)


def arrow(c, x1, y1, x2, y2, color=BLUE, width=1.7, dashed=False):
    c.saveState()
    c.setStrokeColor(color)
    c.setFillColor(color)
    c.setLineWidth(width)
    if dashed:
        c.setDash(4, 3)
    c.line(x1, y1, x2, y2)
    c.setDash()
    angle = atan2(y2 - y1, x2 - x1)
    length = 7
    spread = pi / 7
    path = c.beginPath()
    path.moveTo(x2, y2)
    path.lineTo(x2 - length * cos(angle - spread), y2 - length * sin(angle - spread))
    path.lineTo(x2 - length * cos(angle + spread), y2 - length * sin(angle + spread))
    path.close()
    c.drawPath(path, fill=1, stroke=0)
    c.restoreState()


def box(c, x, y, w, h, title, lines, accent=BLUE, fill=BLUE_LIGHT):
    c.setFillColor(fill)
    c.setStrokeColor(LINE)
    c.roundRect(x, y, w, h, 9, fill=1, stroke=1)
    c.setFillColor(accent)
    c.roundRect(x, y + h - 7, w, 7, 3, fill=1, stroke=0)
    text(c, x + 12, y + h - 27, title, 11, INK, "Helvetica-Bold")
    for index, line in enumerate(lines):
        text(c, x + 12, y + h - 46 - index * 13, line, 8.7, MUTED)


def page_heading(c, title, subtitle, page):
    c.setFillColor(colors.white)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(BLUE)
    c.roundRect(37, PAGE_H - 51, 9, 23, 4, fill=1, stroke=0)
    text(c, 57, PAGE_H - 39, title, 21, INK, "Helvetica-Bold")
    text(c, 58, PAGE_H - 59, subtitle, 10, MUTED)
    c.setStrokeColor(LINE)
    c.setLineWidth(0.8)
    c.line(37, PAGE_H - 72, PAGE_W - 37, PAGE_H - 72)
    text(c, 37, 25, "Sentinel container security monitor", 8.5, MUTED)
    text(c, PAGE_W - 37, 25, f"{page} / 2", 8.5, MUTED, align="right")


def functional_page(c):
    page_heading(c, "Functional diagram", "How the data moves through the application", 1)
    for x, label in [(42, "SOURCES"), (218, "COLLECTORS"), (410, "ANALYSIS"), (620, "STORAGE AND INTERFACE")]:
        text(c, x, 492, label, 8.5, MUTED, "Helvetica-Bold")

    box(c, 42, 349, 138, 113, "Docker Engine", [
        "Lifecycle events", "CPU and memory stats", "Container configuration"
    ])
    box(c, 42, 207, 138, 113, "Kubernetes API", [
        "Pods and events", "Security contexts", "Metrics API, if installed"
    ], TEAL, TEAL_LIGHT)
    box(c, 218, 359, 146, 93, "Docker collector", [
        "Event stream", "Inventory and stats polling"
    ])
    box(c, 218, 217, 146, 93, "K8s collector", [
        "Pod and event polling", "Optional usage metrics"
    ], TEAL, TEAL_LIGHT)
    box(c, 410, 273, 166, 145, "Normalize and detect", [
        "One workload/event format", "Configuration and event rules", "Rolling CPU/memory baseline", "Alert correlation by workload"
    ], AMBER, AMBER_LIGHT)
    box(c, 620, 363, 180, 83, "SQLite", [
        "Workloads, events, samples", "and correlated alerts"
    ])
    box(c, 620, 248, 180, 82, "FastAPI", [
        "Read data and update alerts", "Export incident report"
    ])
    box(c, 620, 133, 180, 82, "React GUI", [
        "Alerts, workloads and events", "Refreshes every 5 seconds"
    ], TEAL, TEAL_LIGHT)
    box(c, 42, 105, 322, 70, "Opt-in test lab", [
        "Privileged and crash-loop workloads reproduce findings",
        "Runs on the Docker or Kubernetes source above"
    ], colors.HexColor("#64748b"), GRAY_LIGHT)

    arrow(c, 180, 405, 218, 405)
    arrow(c, 180, 263, 218, 263, TEAL)
    arrow(c, 364, 405, 410, 392)
    arrow(c, 364, 263, 410, 301, TEAL)
    arrow(c, 576, 370, 620, 405)
    arrow(c, 697, 330, 697, 363)
    arrow(c, 723, 363, 723, 330, TEAL)
    arrow(c, 697, 215, 697, 248, TEAL)
    arrow(c, 723, 248, 723, 215)
    arrow(c, 492, 273, 492, 201, AMBER, 1.3, dashed=True)

    c.setFillColor(GRAY_LIGHT)
    c.roundRect(401, 110, 175, 91, 8, fill=1, stroke=0)
    text(c, 413, 179, "Detection outcome", 9.5, INK, "Helvetica-Bold")
    text(c, 413, 160, "Severity + explanation", 8.7, MUTED)
    text(c, 413, 146, "Suggested action", 8.7, MUTED)
    text(c, 413, 132, "Timeline context", 8.7, MUTED)

    text(c, 42, 70, "Optional AI explanation is requested through FastAPI for a selected alert.", 8.6, MUTED)
    text(c, 42, 56, "Core detection continues to work without the AI service or Kubernetes Metrics API.", 8.6, MUTED)
    c.showPage()


def sequence_message(c, x1, x2, y, label, color=BLUE, dashed=False):
    arrow(c, x1, y, x2, y, color=color, width=1.4, dashed=dashed)
    text(c, (x1 + x2) / 2, y + 8, label, 8.6, INK, align="center")


def sequence_page(c):
    page_heading(c, "Alert sequence diagram", "From a runtime event to a visible and actionable alert", 2)
    lanes = [
        (75, "Docker / K8s"), (214, "Collector"), (353, "Detector"),
        (492, "SQLite"), (631, "FastAPI"), (770, "React GUI")
    ]
    for x, label in lanes:
        c.setFillColor(BLUE_LIGHT if label not in ("SQLite", "React GUI") else TEAL_LIGHT)
        c.setStrokeColor(LINE)
        c.roundRect(x - 57, 457, 114, 34, 7, fill=1, stroke=1)
        text(c, x, 470, label, 9.4, INK, "Helvetica-Bold", "center")
        c.saveState()
        c.setStrokeColor(colors.HexColor("#bdcbdc"))
        c.setDash(3, 4)
        c.line(x, 451, x, 93)
        c.restoreState()

    sequence_message(c, 75, 214, 432, "1 Event occurs")
    sequence_message(c, 214, 492, 394, "2 Normalize and save event")
    sequence_message(c, 214, 353, 356, "3 Evaluate event rule")
    sequence_message(c, 353, 492, 318, "4 Correlate alert", AMBER)
    sequence_message(c, 770, 631, 280, "5 Poll every 5 seconds", TEAL)
    sequence_message(c, 631, 492, 242, "6 Query current alerts")
    sequence_message(c, 631, 770, 204, "7 Return alert and timeline", TEAL, dashed=True)
    sequence_message(c, 770, 631, 166, "8 Acknowledge or resolve", TEAL)
    sequence_message(c, 631, 492, 128, "9 Save new alert status")

    c.setFillColor(GRAY_LIGHT)
    c.roundRect(38, 48, PAGE_W - 76, 34, 7, fill=1, stroke=0)
    text(c, 50, 68, "The same collector and detector path also evaluates configuration findings and CPU/memory anomalies.", 8.7, MUTED)
    text(c, 50, 54, "The GUI can inspect workload details or export a report after the alert appears.", 8.7, MUTED)
    c.showPage()


pdf = canvas.Canvas(str(PDF), pagesize=(PAGE_W, PAGE_H), pageCompression=1)
pdf.setTitle("Sentinel Project Diagrams")
pdf.setAuthor("Marwan Fayad")
functional_page(pdf)
sequence_page(pdf)
pdf.save()

document = pdfium.PdfDocument(str(PDF))
if len(document) != 2:
    raise RuntimeError(f"Expected 2 pages, got {len(document)}")
names = ["Sentinel_Functional_Diagram.png", "Sentinel_Alert_Sequence_Diagram.png"]
for index, page in enumerate(document):
    page.render(scale=3).to_pil().convert("RGB").save(OUT / names[index], dpi=(216, 216))
print(PDF)
for name in names:
    print(OUT / name)
