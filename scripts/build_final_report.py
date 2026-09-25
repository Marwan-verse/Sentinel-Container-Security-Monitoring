"""Build the Sentinel academic final report from the current project files."""

from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT, WD_SECTION_START
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Sentinel_Final_Report_Marwan_Fayad.docx"
BLUE = RGBColor(28, 63, 125)
BLACK = RGBColor(0, 0, 0)
GRAY = RGBColor(83, 94, 111)


def set_cell_shading(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def set_cell_border(cell, color="D9D9D9"):
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = tc_pr.first_child_found_in("w:tcBorders")
    if borders is None:
        borders = OxmlElement("w:tcBorders")
        tc_pr.append(borders)
    for edge in ("top", "left", "bottom", "right"):
        tag = "w:" + edge
        el = borders.find(qn(tag))
        if el is None:
            el = OxmlElement(tag)
            borders.append(el)
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:color"), color)


def set_cell_margin(cell, top=110, start=120, bottom=110, end=120):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    mar = tc_pr.first_child_found_in("w:tcMar")
    if mar is None:
        mar = OxmlElement("w:tcMar")
        tc_pr.append(mar)
    for side, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        tag = "w:" + side
        item = mar.find(qn(tag))
        if item is None:
            item = OxmlElement(tag)
            mar.append(item)
        item.set(qn("w:w"), str(value))
        item.set(qn("w:type"), "dxa")


def table(headers, rows, widths):
    result = doc.add_table(rows=1, cols=len(headers))
    result.autofit = False
    for i, (header, width) in enumerate(zip(headers, widths)):
        result.columns[i].width = Inches(width)
        cell = result.rows[0].cells[i]
        cell.width = Inches(width)
        cell.text = header
        set_cell_shading(cell, "183A66")
        for run in cell.paragraphs[0].runs:
            run.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)
            run.font.size = Pt(9)
    for row_index, values in enumerate(rows):
        cells = result.add_row().cells
        for i, (value, width) in enumerate(zip(values, widths)):
            cells[i].width = Inches(width)
            cells[i].text = str(value)
            if row_index % 2:
                set_cell_shading(cells[i], "F2F6FB")
            for paragraph in cells[i].paragraphs:
                paragraph.paragraph_format.space_after = Pt(0)
                for run in paragraph.runs:
                    run.font.size = Pt(9)
    for row in result.rows:
        for cell in row.cells:
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_border(cell)
            set_cell_margin(cell)
    result.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    doc.add_paragraph().paragraph_format.space_after = Pt(0)
    return result


def add_p(text="", style=None):
    p = doc.add_paragraph(style=style)
    p.add_run(text)
    return p


def add_bullet(text):
    p = add_p(text, "List Bullet")
    p.paragraph_format.space_after = Pt(2)
    return p


def heading(text, level=1):
    return doc.add_heading(text, level=level)


def source_code(path, first, last):
    lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
    return "\n".join(lines[first - 1:last])


def code_block(label, path, first, last):
    caption = doc.add_paragraph()
    caption.style = doc.styles["Caption"]
    caption.add_run(f"{label}  {path}, lines {first}–{last}")
    caption.paragraph_format.keep_with_next = True
    p = doc.add_paragraph(style="Code Block")
    p.add_run(source_code(path, first, last))
    p.paragraph_format.keep_together = True
    p.paragraph_format.space_after = Pt(9)


def add_page_field(paragraph):
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = "PAGE"
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    value = OxmlElement("w:t")
    value.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    for el in (begin, instruction, separate, value, end):
        run._r.append(el)


def setup_section(section, landscape=False):
    section.orientation = WD_ORIENT.LANDSCAPE if landscape else WD_ORIENT.PORTRAIT
    section.page_width = Inches(11 if landscape else 8.5)
    section.page_height = Inches(8.5 if landscape else 11)
    section.top_margin = Inches(0.72)
    section.bottom_margin = Inches(0.67)
    section.left_margin = Inches(0.78 if landscape else 0.84)
    section.right_margin = Inches(0.78 if landscape else 0.84)
    section.header_distance = Inches(0.35)
    section.footer_distance = Inches(0.35)
    section.header.is_linked_to_previous = False
    section.footer.is_linked_to_previous = False
    header = section.header.paragraphs[0]
    header.text = "SENTINEL  |  FINAL REPORT"
    header.style = doc.styles["Header"]
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    footer.add_run("Marwan Fayad and team  ·  ")
    add_page_field(footer)


doc = Document()
setup_section(doc.sections[0])
styles = doc.styles
styles["Normal"].font.name = "Aptos"
styles["Normal"].font.size = Pt(10.5)
styles["Normal"].font.color.rgb = BLACK
styles["Normal"].paragraph_format.line_spacing = 1.12
styles["Normal"].paragraph_format.space_after = Pt(7)

for name, size, before, after in (("Title", 22, 0, 10), ("Heading 1", 15, 19, 8), ("Heading 2", 11.5, 12, 5), ("Heading 3", 10.5, 9, 3)):
    style = styles[name]
    style.font.name = "Aptos Display" if name == "Title" else "Aptos"
    style.font.size = Pt(size)
    style.font.bold = True
    style.font.color.rgb = BLACK
    style.paragraph_format.space_before = Pt(before)
    style.paragraph_format.space_after = Pt(after)
    style.paragraph_format.keep_with_next = True

title_ppr = styles["Title"]._element.get_or_add_pPr()
for element in list(title_ppr):
    if element.tag == qn("w:pBdr"):
        title_ppr.remove(element)

styles["Subtitle"].font.name = "Aptos"
styles["Subtitle"].font.size = Pt(12)
styles["Subtitle"].font.color.rgb = BLACK
styles["Subtitle"].font.italic = False
styles["Subtitle"].paragraph_format.space_after = Pt(14)
styles["Caption"].font.name = "Aptos"
styles["Caption"].font.size = Pt(8.5)
styles["Caption"].font.color.rgb = GRAY
styles["Caption"].paragraph_format.space_before = Pt(4)
styles["Caption"].paragraph_format.space_after = Pt(4)
styles["Header"].font.name = "Aptos"
styles["Header"].font.size = Pt(7.5)
styles["Header"].font.color.rgb = GRAY

code_style = styles.add_style("Code Block", 1)
code_style.font.name = "Consolas"
code_style.font.size = Pt(8.2)
code_style.font.color.rgb = RGBColor(28, 39, 55)
code_style.paragraph_format.left_indent = Inches(0.16)
code_style.paragraph_format.right_indent = Inches(0.08)
code_style.paragraph_format.space_before = Pt(2)
code_style.paragraph_format.space_after = Pt(7)
code_style.paragraph_format.line_spacing = 1.0


# Title and Section 1
doc.add_paragraph("Sentinel Container Security Monitor Final Report", style="Title")
doc.add_paragraph("Implementation methodology code explanation and team contribution", style="Subtitle")
meta = add_p("Prepared by Marwan Fayad, Bohdan Klymov, Ihor Maslovskyi and Nazariy Buryak")
meta.paragraph_format.space_after = Pt(2)
meta = add_p("25 September 2026")
meta.paragraph_format.space_after = Pt(17)

heading("1 Introduction CA 1")
add_p("Sentinel is a small security monitor for Docker containers and Kubernetes pods. It collects workload settings, lifecycle events and CPU and memory measurements, then turns them into alerts that a user can inspect in a simple browser dashboard. This report explains how the completed prototype is organised, how its detections work, and what the current tests establish.")
heading("1.1 Problem and aim", 2)
add_p("Docker and Kubernetes expose useful security signals through different interfaces. A user may have to check container configuration, pod status, events and resource data separately to understand a failure or risky setting. Sentinel brings those signals into one workload record and makes the reason for each alert visible. The intended setting is a small local or teaching environment where clarity and repeatable demonstrations matter.")
heading("1.2 Project objectives", 2)
for item in (
    "Observe Docker containers and Kubernetes pods with collectors that use a common workload format.",
    "Detect risky configuration, failure events and unusual resource changes with explainable rules.",
    "Store workloads, events, samples and correlated alerts in SQLite.",
    "Show a simple dashboard for live alerts, workload details, event history and report export.",
    "Provide optional insecure lab workloads for controlled demonstrations."
):
    add_bullet(item)
heading("1.3 Scope and result", 2)
add_p("The repository contains the Python collector and detection service, a FastAPI application, a React dashboard, Docker and Kubernetes deployment files, and opt-in demonstration workloads. AI wording for an individual alert is optional; the rule engine runs without it. The dashboard shown later uses seeded demo data. Automated tests and the frontend build pass, but live Docker and Kubernetes collection were not exercised in this workspace, so runtime compatibility remains an integration test for the target environment.")


# Section 2 methodology, including the two diagrams from CA 2.
method_heading = heading("2 Methodology CA 2")
method_heading.paragraph_format.page_break_before = True
add_p("We developed the system in four connected stages. First, Docker events, statistics, SQLite storage and configuration rules established the data path. Second, recent resource samples provided a rolling baseline, while alert fingerprints grouped repeat findings. Third, FastAPI exposed that data and a deliberately simple React page presented it. Finally, optional AI explanations, an incident report and insecure lab manifests supported investigation and demonstration.")
table(
    ("Stage", "Implementation and output"),
    (
        ("Collection", "Docker event stream and statistics polling; Kubernetes pod and event polling; optional Kubernetes Metrics API."),
        ("Normalisation", "Both platforms become workload records with source, name, state, restart count and security details."),
        ("Detection", "Configuration and failure rules plus a rolling CPU and memory comparison create scored alerts."),
        ("Presentation", "SQLite stores evidence; FastAPI provides JSON routes; React refreshes the dashboard every five seconds."),
    ),
    (1.28, 5.54),
)
heading("2.1 Data and analysis flow", 2)
add_p("The Docker collector reads container settings, lifecycle events and resource statistics. The Kubernetes collector reads pod specifications, status and warning events, and asks the Metrics API for usage when it is installed. Both collectors produce the same internal workload fields. The detector evaluates those fields and writes events and alerts through the store. The web API queries the store, while the dashboard shows the latest state. Figure 1 gives the full functional view.")
heading("2.2 Validation method", 2)
add_p("Automated tests cover the API and demo data, alert correlation and resolution, Docker and Kubernetes normalisation, quantity conversion and the optional explanation path with a mock. The UI build checks that the React source compiles. The opt-in Docker Compose and Kubernetes lab files provide privileged and failure examples for later live demonstrations. This report distinguishes those prepared demonstrations from runtime tests actually performed here.")

landscape = doc.add_section(WD_SECTION_START.NEW_PAGE)
setup_section(landscape, True)
heading("2.3 Functional diagram", 2)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run().add_picture(str(ROOT / "diagrams" / "Sentinel_Functional_Diagram.png"), width=Inches(9.15))
p.paragraph_format.space_after = Pt(2)
p = doc.add_paragraph("Figure 1  Sources, collectors, detection, storage and interface", style="Caption")
p.alignment = WD_ALIGN_PARAGRAPH.CENTER

landscape2 = doc.add_section(WD_SECTION_START.NEW_PAGE)
setup_section(landscape2, True)
heading("2.4 Alert sequence diagram", 2)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run().add_picture(str(ROOT / "diagrams" / "Sentinel_Alert_Sequence_Diagram.png"), width=Inches(9.15))
p.paragraph_format.space_after = Pt(2)
p = doc.add_paragraph("Figure 2  From a runtime event to an alert and an updated status", style="Caption")
p.alignment = WD_ALIGN_PARAGRAPH.CENTER

portrait = doc.add_section(WD_SECTION_START.NEW_PAGE)
setup_section(portrait)


# Section 3 code explanation.
heading("3 Code Explanation")
add_p("The implementation separates collection, detection, persistence and presentation. The excerpts below are copied from the repository; each is followed by its role in the running system.")
table(
    ("File", "Purpose"),
    (
        ("sentinel/collectors.py", "Reads Docker and Kubernetes state and converts it to a common workload format."),
        ("sentinel/detect.py", "Applies configuration, event and resource anomaly rules."),
        ("sentinel/store.py", "Creates SQLite tables and manages workloads, samples, events and alerts."),
        ("sentinel/api.py", "Serves JSON routes, alert actions, reports and the built dashboard."),
        ("frontend/src/main.jsx", "Renders the one-page GUI and refreshes data every five seconds."),
        ("lab/compose.yaml and lab/kubernetes.yaml", "Define opt-in insecure workloads for controlled demonstrations."),
    ),
    (2.15, 4.67),
)

heading("3.1 Collectors and a common workload record", 2)
add_p("CollectorManager starts separate background loops for Docker polling, Docker events and Kubernetes polling according to SENTINEL_MODE. Docker and Kubernetes objects are normalised by docker_item and kubernetes_item into fields such as key, source, name, state, restarts and details. This lets the same detection functions process both sources.")
code_block("Excerpt 1", "sentinel/collectors.py", 103, 109)
add_p("The Docker polling loop upserts a workload, checks its configuration, compares restart counts and records CPU and memory. The event loop listens for lifecycle events. The Kubernetes loop reads pods and events; usage sampling depends on the optional Metrics API.")

heading("3.2 SQLite and alert correlation", 2)
add_p("Store creates four tables: containers, events, samples and alerts. SQLite write-ahead logging supports the background collectors and API reads. Event keys are unique, so a repeated event import is ignored. Each alert has a fingerprint made from its workload and rule. Repeated matches update the existing row and increase count, while a resolved finding reopens if it happens again.")
code_block("Excerpt 2", "sentinel/store.py", 106, 108)
add_p("When a configuration problem is no longer present, resolve_configuration marks its open alert resolved. The sample table retains only the most recent 120 points per workload, which bounds local storage growth for resource history.")

heading("3.3 Detection and anomaly scoring", 2)
add_p("Configuration rules look for privileged mode, a Docker socket mount, host PID or networking, host mounts, root execution, privilege escalation and sensitive Linux capabilities. Event rules flag out-of-memory termination, repeated start failure, unexpected exits and Kubernetes warnings. Each finding stores a title, severity, evidence text and recommended action.")
code_block("Excerpt 3", "sentinel/detect.py", 85, 97)
add_p("Resource detection compares a new value with up to 30 previous samples and waits until at least eight exist. It requires an absolute jump, a rise of at least three population standard deviations and a value at least 1.5 times the mean. The resulting score is capped at 100. These fixed thresholds make the prototype explainable, although they can miss slow changes or react differently to bursty workloads.")

heading("3.4 FastAPI routes and incident output", 2)
add_p("The API exposes health, summary, workload list and detail, alerts, events, alert status changes, optional AI explanations and a Markdown incident report. The workload detail route combines the current record with its alerts, events and recent samples, so the GUI can show the evidence behind one alert.")
code_block("Excerpt 4", "sentinel/api.py", 43, 49)
add_p("The status route accepts only open, acknowledged or resolved. The explanation route returns an error when no API key is configured. The incident report endpoint exports open findings and recent events as Markdown.")

heading("3.5 Simple React dashboard", 2)
add_p("The React page fetches summary, collector health, alerts, workloads and events together, then refreshes every five seconds. It presents the highest-priority alerts first, allows search and alert actions, and opens workload details in a modal. The interface keeps the daily investigation path on one page.")
code_block("Excerpt 5", "frontend/src/main.jsx", 39, 59)

doc.add_page_break()
heading("3.6 Interface screenshot and test evidence", 2)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run().add_picture(str(ROOT / ".playwright-cli" / "page-2026-09-25T18-09-44-246Z.png"), width=Inches(6.78))
p.paragraph_format.space_after = Pt(2)
p = doc.add_paragraph("Figure 3  One-page Sentinel dashboard with seeded demonstration alerts", style="Caption")
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
add_p("The screenshot shows the demo-data indicator, workload and alert counts, search field and risk-ranked alert list. The displayed example is a privileged Docker workload with an explicit suggested action. It demonstrates the presentation flow; the screenshot does not prove a live container connection.")
table(
    ("Check", "Result", "Meaning"),
    (
        ("Python tests", "4 passed", "API, correlation, normalisation and mocked AI path completed."),
        ("Frontend build", "Passed", "Vite compiled the React dashboard for serving by FastAPI."),
        ("Live Docker and Kubernetes", "Pending", "Collectors and manifests require target runtimes for integration verification."),
    ),
    (1.45, 1.1, 4.27),
)
add_p("Operational limits: the Docker socket gives the monitoring process broad access to its host daemon; it should be used only in a trusted environment. The included insecure workloads are opt-in and intended for an isolated lab. Kubernetes resource anomaly alerts require the Metrics API. The prototype has no built-in authentication, so deployment should restrict network access to the dashboard and API.")


# Section 4 records only the user-confirmed equal split.
contribution_heading = heading("4 Contribution of Each Member")
contribution_heading.paragraph_format.page_break_before = True
add_p("The team reported an equal contribution split. Individual feature ownership was not specified, so the percentages below describe the overall project contribution rather than assigning particular code files or report sections to one person.")
table(
    ("Member", "Student ID", "Contribution"),
    (
        ("Marwan Fayad", "Not supplied", "25%"),
        ("Bohdan Klymov", "C00325691", "25%"),
        ("Ihor Maslovskyi", "C00305614", "25%"),
        ("Nazariy Buryak", "C00315320", "25%"),
    ),
    (2.55, 2.05, 2.22),
)
add_p("Total contribution: 100%.")

doc.core_properties.title = "Sentinel Container Security Monitor Final Report"
doc.core_properties.subject = "Methodology, code explanation and team contribution"
doc.core_properties.author = "Marwan Fayad and team"
doc.save(OUTPUT)
print(OUTPUT)
