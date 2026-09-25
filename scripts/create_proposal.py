from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "Sentinel_Project_Proposal_Marwan_Fayad.docx"


def add_body(document, text):
    paragraph = document.add_paragraph(text, style="Normal")
    paragraph.paragraph_format.keep_together = True
    return paragraph


def add_numbered(document, number, label, text):
    paragraph = document.add_paragraph(style="Normal")
    paragraph.paragraph_format.left_indent = Inches(0.23)
    paragraph.paragraph_format.first_line_indent = Inches(-0.23)
    paragraph.paragraph_format.space_after = Pt(5)
    paragraph.add_run(f"{number}. {label}: ").bold = True
    paragraph.add_run(text)
    paragraph.paragraph_format.keep_together = True
    return paragraph


def add_step(document, number, text):
    paragraph = document.add_paragraph(style="Normal")
    paragraph.paragraph_format.space_after = Pt(8)
    paragraph.add_run(f"Step #{number}: ").bold = True
    paragraph.add_run(text)
    paragraph.paragraph_format.keep_together = True
    return paragraph


doc = Document()
section = doc.sections[0]
section.top_margin = Inches(0.82)
section.bottom_margin = Inches(0.73)
section.left_margin = Inches(0.95)
section.right_margin = Inches(0.95)

styles = doc.styles
normal = styles["Normal"]
normal.font.name = "Aptos"
normal.font.size = Pt(10.5)
normal.font.color.rgb = RGBColor(0, 0, 0)
normal.paragraph_format.space_after = Pt(7)
normal.paragraph_format.line_spacing = 1.16

title = styles["Title"]
title.font.name = "Aptos Display"
title.font.size = Pt(22)
title.font.bold = True
title.font.color.rgb = RGBColor(0, 0, 0)
title.paragraph_format.space_after = Pt(4)
for border in title._element.xpath(".//w:pBdr"):
    border.getparent().remove(border)

heading = styles["Heading 1"]
heading.font.name = "Aptos Display"
heading.font.size = Pt(13)
heading.font.bold = True
heading.font.color.rgb = RGBColor(0, 0, 0)
heading.paragraph_format.space_before = Pt(12)
heading.paragraph_format.space_after = Pt(5)
heading.paragraph_format.keep_with_next = True

footer = section.footer.paragraphs[0]
footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
footer.style = styles["Normal"]
footer.paragraph_format.space_after = Pt(0)
footer.add_run("Marwan Fayad  |  ").font.size = Pt(9)
field = OxmlElement("w:fldSimple")
field.set(qn("w:instr"), "PAGE")
footer._p.append(field)

doc.add_paragraph("Sentinel Container Security Monitoring", style="Title")
subtitle = doc.add_paragraph()
subtitle.paragraph_format.space_after = Pt(15)
run = subtitle.add_run("Project Proposal")
run.bold = True
run.font.size = Pt(12)
author = doc.add_paragraph()
author.paragraph_format.space_after = Pt(19)
author.add_run("Marwan Fayad").bold = True

doc.add_heading("Introduction", level=1)
add_body(doc, "Sentinel is a proposed security monitoring tool for Docker containers and Kubernetes pods. It brings workload settings, runtime events and resource use into one simple interface. Its purpose is to help a user notice risky configurations and unusual behaviour, then understand which workload needs attention.")
add_body(doc, "Containers make it practical to package and run applications, but their security depends on how they are configured and operated. Docker exposes lifecycle events and resource statistics, while Kubernetes provides pod status, events and security settings. These signals are useful, but reviewing them separately can make a small environment harder to monitor. Sentinel will collect them, store them in SQLite and display correlated findings in a browser dashboard.")
add_body(doc, "The project will be evaluated with deliberately insecure workloads in an isolated test environment. This provides repeatable examples of privileged containers, root execution and failed starts without relying on a real incident.")

doc.add_heading("Problem Statement", level=1)
add_body(doc, "A user responsible for a Docker host or Kubernetes cluster may not have an immediate view of which workloads run with excessive privileges or show signs of failure. Events, configuration data and CPU or memory measurements are available through different interfaces. The problem addressed by this project is how to combine those signals into a clear, timely view that helps the user identify and investigate potential security issues.")

doc.add_heading("Motivation", level=1)
add_body(doc, "The aim is to make container security monitoring approachable for a small project or learning environment. The dashboard should show what happened, which workload is affected and why an alert matters. The tool will favour a straightforward setup and explanations that can be checked against the underlying event or configuration, while still supporting both Docker and Kubernetes.")

doc.add_page_break()

add_body(doc, "Sentinel will be built with Python for collection and detection, FastAPI for the application interface, SQLite for local storage and React for the dashboard. The following features define the proposed system:")
add_numbered(doc, 1, "Docker event collection", "Record container lifecycle events such as start, stop, exit and out-of-memory activity.")
add_numbered(doc, 2, "Kubernetes observation", "Read pod inventory and events across namespaces, with CPU and memory measurements when the cluster provides the Metrics API.")
add_numbered(doc, 3, "Configuration detection", "Flag privileged workloads, root users, host namespace access, host mounts, Docker socket mounts and sensitive capabilities.")
add_numbered(doc, 4, "Behavioural baselines", "Compare recent CPU and memory samples with a rolling baseline and score unusually large changes.")
add_numbered(doc, 5, "Alert correlation", "Group repeated findings by workload and rule, preserve an event timeline and allow alerts to be acknowledged or resolved.")
add_numbered(doc, 6, "Simple dashboard", "Show live alerts, searchable workload details, resource trends and an event timeline in one browser interface.")
add_numbered(doc, 7, "Reports and test lab", "Export a concise incident report and provide optional insecure Docker and Kubernetes workloads for repeatable demonstrations.")

doc.add_heading("Justification", level=1)
add_body(doc, "Kubernetes Pod Security Standards identify privileged containers, host namespaces and hostPath volumes as settings that weaken isolation. A monitoring tool that makes these settings visible can support review and remediation. Docker also exposes container events and resource statistics that can provide context when a workload exits or its resource use changes.")
add_body(doc, "Sentinel combines these data sources in a small local application. A basic rule should explain the exact setting or event that triggered it, while the baseline should highlight a change only after enough samples have been collected. The result is intended to help the user investigate; it is not a substitute for cluster policy enforcement, vulnerability scanning or a full incident response process.")
add_body(doc, "An optional AI explanation can restate a selected alert and its recent evidence in plain language. It must distinguish observed facts from possible causes, and the core detections must continue to work without an AI service.")

doc.add_page_break()

doc.add_heading("Specific Items to be Addressed", level=1)
add_body(doc, "Development and evaluation will follow these steps:")
add_step(doc, 1, "Define the information needed from Docker and Kubernetes and decide which events, settings and measurements can be collected with read-only access.")
add_step(doc, 2, "Build the Docker event collector, container statistics collector and SQLite data model. Add initial rules for clearly risky settings and failure events.")
add_step(doc, 3, "Add Kubernetes pod and event collection. Verify the same dashboard can describe workloads from either platform.")
add_step(doc, 4, "Implement rolling behavioural baselines, anomaly scores and alert correlation. Record an event timeline for each workload.")
add_step(doc, 5, "Create the FastAPI endpoints and React dashboard, including live alerts, container detail pages and incident report export.")
add_step(doc, 6, "Create opt-in insecure lab workloads for Docker and Kubernetes. Test that expected alerts appear, repeated events are grouped and resolved configurations no longer remain open.")
add_step(doc, 7, "Review the interface and documentation, run automated tests and describe the limits of the prototype, including its reliance on Kubernetes Metrics Server for resource samples.")

doc.add_heading("References", level=1)
references = [
    ("Docker Docs. Docker system events.", "https://docs.docker.com/reference/cli/docker/system/events/"),
    ("Docker Docs. Docker container stats.", "https://docs.docker.com/reference/cli/docker/container/stats/"),
    ("Kubernetes. Pod Security Standards.", "https://kubernetes.io/docs/concepts/security/pod-security-standards/"),
    ("Kubernetes. Resource metrics pipeline.", "https://kubernetes.io/docs/tasks/debug/debug-cluster/resource-metrics-pipeline/"),
]
for title_text, url in references:
    paragraph = doc.add_paragraph(style="Normal")
    paragraph.paragraph_format.space_after = Pt(3)
    paragraph.add_run(title_text + " ").bold = True
    paragraph.add_run(url)

doc.core_properties.title = "Sentinel Container Security Monitoring Project Proposal"
doc.core_properties.author = "Marwan Fayad"
doc.core_properties.subject = "Docker and Kubernetes security monitoring project proposal"
doc.save(OUTPUT)
print(OUTPUT)
