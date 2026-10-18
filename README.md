# Lynis UI Graphical Report
Local web UI for running a full Lynis security audit in real time, with live colored output and a color-coded PDF report. Single Python file, no dependencies.

# Lynis Audit Console
A single-file Python app that wraps Lynis in a local web interface, so you can run a full system security audit from your browser and export the results as a PDF.

# What it does:
+ System info: the header shows your OS, kernel, architecture, host and Lynis version.
+ Root password: a dialog asks for it when you click Start audit. It is checked with sudo, piped to sudo -S, and never stored or logged. A wrong password is rejected before anything runs.
+ Local only: the server listens on 127.0.0.1 and uses a random per-session token. It also checks the Host header.
+ Real-time output: Lynis output streams into the page line by line, with section headers highlighted and status words colored (green OK, orange suggestion/notice, red warning/weak). There is a Stop button.
+ Modes (they can be combined; with none selected it runs a full lynis audit system):
- Quick: --quick, so Lynis doesn’t pause between sections.
- Warning: --warnings-only.
- Test: --tests ID…, or --tests-from-group if you tick “by group” (for example ssh or firewalls).
+ PDF report: after the run, the Report tab shows a summary (hardening index, tests performed, warnings, suggestions, checks OK) and every section as a separate colored block. Warnings and suggestions get their own red and orange blocks with the Lynis control links. “Download PDF report” opens the print dialog with an A4 layout that keeps the colors; choose “Save as PDF” there. “Save raw log” also saves the plain text.

The PDF goes through the browser’s print dialog rather than a file download. That avoids adding extra dependencies and works offline. The report is built from Lynis’s console output, not from /var/log/lynis-report.dat.

# Features:
+ Shows your OS, kernel, architecture, host and Lynis version
+ Asks for your root/sudo password before it runs (passed to sudo -S, never stored or logged)
+ Streams the audit output live, with colored statuses and section headers
+ Supports Quick mode, Warning mode (warnings only) and Test mode (specific test IDs or groups)
+ Builds a color-coded report with a summary, warnings, suggestions and every section, then exports it as a PDF via the browser’s print dialog (“Save as PDF”)
+ Python standard library only; the server listens on 127.0.0.1 and uses a per-session token

# Usage:
python3 lynis_audit_ui.py   # run as a normal user, not with sudo

# Requirements:
Linux, Python 3.8+, Lynis, sudo, and a modern browser.
