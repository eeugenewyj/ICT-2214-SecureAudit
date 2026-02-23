import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import sys
import io
import json
from datetime import datetime

# NEW: use the updated crawler
from crawler import HTMLCrawler


class NeonStyle:
    BG = "#0c1020"
    PANEL = "#121a2f"
    PANEL_2 = "#0f162a"
    BORDER = "#1f2a44"
    TEXT = "#e7eefc"
    MUTED = "#93a4c7"
    CYAN = "#00d5ff"
    RED = "#ff2a3d"
    ORANGE = "#ff8a2a"
    YELLOW = "#ffd02a"
    GREEN = "#2aff8a"


def severity_normalize(sev: str) -> str:
    """
    crawler.py uses uppercase severities (HIGH/MEDIUM/etc).
    GUI expects Title case (High/Medium/etc).
    """
    if not sev:
        return "Low"
    s = str(sev).strip()
    upper = s.upper()
    if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return upper.title()
    # already title-case or unknown
    return s.title()


def severity_to_rank(sev: str) -> int:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    return order.get(sev, 0)


def risk_label_and_color(vulns):
    if not vulns:
        return "NONE", NeonStyle.GREEN

    max_sev = max((v.get("severity", "") for v in vulns), key=severity_to_rank, default="")
    if max_sev == "Critical":
        return "CRITICAL", NeonStyle.RED
    if max_sev == "High":
        return "HIGH", NeonStyle.RED
    if max_sev == "Medium":
        return "MEDIUM", NeonStyle.ORANGE
    if max_sev == "Low":
        return "LOW", NeonStyle.YELLOW
    return "UNKNOWN", NeonStyle.MUTED


def build_recommendations(vulns):
    """
    crawler.py does not print a recommendation block.
    Generate remediation guidance based on vulnerability types detected.
    """
    if not vulns:
        return (
            "✅ No issues detected.\n\n"
            "Keep these controls in place:\n"
            "• Server-side validation\n"
            "• Output encoding for user-controlled data\n"
            "• CSRF tokens + SameSite cookies\n"
            "• Safe DOM APIs (textContent) instead of innerHTML\n"
            "• Security headers (CSP, HSTS, XFO, XCTO)\n"
        )

    types = {v.get("type", "") for v in vulns}
    recs = []

    # XSS
    if "XSS" in types:
        recs.extend([
            "XSS:",
            "1) Prefer textContent/createTextNode over innerHTML/outerHTML",
            "2) Encode output based on context (HTML/attr/JS/URL)",
            "3) Add a strict Content-Security-Policy (CSP) to reduce impact",
            ""
        ])

    # CSRF
    if "CSRF" in types:
        recs.extend([
            "CSRF:",
            "1) Add CSRF tokens to all state-changing POST/PUT/DELETE forms/requests",
            "2) Validate Origin/Referer on sensitive endpoints",
            "3) Use SameSite=Lax/Strict cookies where possible",
            ""
        ])

    # SQLi (crawler type is 'SQLI')
    if "SQLI" in types:
        recs.extend([
            "SQL Injection:",
            "1) Use parameterized queries / prepared statements everywhere",
            "2) Avoid string concatenation in SQL queries",
            "3) Apply least-privilege DB accounts and safe error handling (no SQL error leakage)",
            ""
        ])

    # Security headers
    if "SECURITY_HEADER" in types:
        recs.extend([
            "Security Headers:",
            "1) Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
            "2) Add Strict-Transport-Security if you enforce HTTPS",
            ""
        ])

    # Cookies
    if "COOKIE_SECURITY" in types:
        recs.extend([
            "Cookie Hardening:",
            "1) Mark session cookies as Secure + HttpOnly",
            "2) Set SameSite=Lax/Strict unless cross-site flows require None;Secure",
            ""
        ])

    # Third-party / dependency issues
    if any(t in types for t in ("THIRD_PARTY_LIBRARY", "INSECURE_DEPENDENCY", "EXTERNAL_SERVICE")):
        recs.extend([
            "Dependencies / Third-party:",
            "1) Pin versions and patch outdated libraries",
            "2) Remove unused libraries and avoid loading JS from untrusted CDNs",
            ""
        ])

    # Generic baseline
    recs.extend([
        "Baseline:",
        "• Implement server-side validation for all inputs",
        "• Add rate limiting + logging on auth / sensitive endpoints",
        "• Keep secrets out of client-side code",
    ])

    # De-duplicate while preserving order
    seen = set()
    final = []
    for line in recs:
        key = line.strip().lower()
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        final.append(line)

    return "\n".join(final).strip()


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Vulnerability Analyzer")
        self.root.geometry("1200x720")
        self.root.configure(bg=NeonStyle.BG)

        self.last_output_text = ""
        self.last_vulns = []
        self.last_target = ""
        self.last_report = None

        self._build_styles()
        self._build_layout()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Neon.TFrame", background=NeonStyle.BG)
        style.configure("Panel.TFrame", background=NeonStyle.PANEL, bordercolor=NeonStyle.BORDER, relief="solid")
        style.configure("Panel2.TFrame", background=NeonStyle.PANEL_2, bordercolor=NeonStyle.BORDER, relief="solid")

        style.configure("Neon.TLabel", background=NeonStyle.BG, foreground=NeonStyle.TEXT, font=("Segoe UI", 11))
        style.configure("Title.TLabel", background=NeonStyle.BG, foreground=NeonStyle.CYAN, font=("Segoe UI", 26, "bold"))
        style.configure("SubTitle.TLabel", background=NeonStyle.BG, foreground=NeonStyle.MUTED, font=("Segoe UI", 11))

        style.configure("PanelTitle.TLabel", background=NeonStyle.PANEL, foreground=NeonStyle.CYAN, font=("Segoe UI", 14, "bold"))
        style.configure("PanelTitle2.TLabel", background=NeonStyle.PANEL_2, foreground=NeonStyle.CYAN, font=("Segoe UI", 14, "bold"))

        style.configure("Neon.TButton", font=("Segoe UI", 11, "bold"), padding=(14, 10))
        style.map("Neon.TButton",
                  background=[("active", NeonStyle.CYAN), ("!active", NeonStyle.CYAN)],
                  foreground=[("active", "#001018"), ("!active", "#001018")])

        style.configure("Export.TButton", font=("Segoe UI", 11, "bold"), padding=(14, 10))
        style.map("Export.TButton",
                  background=[("active", "#0aa0c2"), ("!active", "#0aa0c2")],
                  foreground=[("active", "#001018"), ("!active", "#001018")])

        style.configure("Neon.Horizontal.TProgressbar",
                        troughcolor=NeonStyle.PANEL_2,
                        bordercolor=NeonStyle.BORDER,
                        background=NeonStyle.CYAN,
                        lightcolor=NeonStyle.CYAN,
                        darkcolor=NeonStyle.CYAN)

    def _build_layout(self):
        header = ttk.Frame(self.root, style="Neon.TFrame")
        header.pack(fill=tk.X, padx=18, pady=(18, 10))

        ttk.Label(header, text="Web Vulnerability Analyzer", style="Title.TLabel").pack(anchor="center")
        ttk.Label(
            header,
            text="Crawler-based scan (directory/file enumeration + HTML/static analysis + third-party signals)",
            style="SubTitle.TLabel"
        ).pack(anchor="center", pady=(6, 0))

        main = ttk.Frame(self.root, style="Neon.TFrame")
        main.pack(fill=tk.BOTH, expand=True, padx=18, pady=12)

        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        left = ttk.Frame(main, style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        ttk.Label(left, text="🖥  Target Input", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w", padx=16, pady=(14, 10))

        url_row = ttk.Frame(left, style="Panel.TFrame")
        url_row.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        url_row.columnconfigure(0, weight=1)

        self.url_var = tk.StringVar(value="https://local.test.com")
        url_entry = tk.Entry(
            url_row,
            textvariable=self.url_var,
            bg="#0b1226",
            fg=NeonStyle.TEXT,
            insertbackground=NeonStyle.CYAN,
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightbackground=NeonStyle.BORDER,
            highlightcolor=NeonStyle.CYAN,
            font=("Consolas", 12)
        )
        url_entry.grid(row=0, column=0, sticky="ew", ipady=8, padx=(0, 10))

        self.scan_btn = ttk.Button(url_row, text="Analyze", style="Neon.TButton", command=self.start_scan)
        self.scan_btn.grid(row=0, column=1, sticky="e")

        self.output = scrolledtext.ScrolledText(
            left,
            wrap=tk.WORD,
            bg="#070d1a",
            fg=NeonStyle.TEXT,
            insertbackground=NeonStyle.CYAN,
            relief="solid",
            bd=1,
            font=("Consolas", 10)
        )
        self.output.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 10))

        bottom = ttk.Frame(left, style="Panel.TFrame")
        bottom.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 14))
        bottom.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(bottom, mode="indeterminate", style="Neon.Horizontal.TProgressbar")
        self.progress.grid(row=0, column=0, sticky="ew", pady=(6, 6))

        btns = ttk.Frame(bottom, style="Panel.TFrame")
        btns.grid(row=1, column=0, sticky="ew")
        btns.columnconfigure(0, weight=1)

        self.export_btn = ttk.Button(btns, text="Export Report", style="Export.TButton", command=self.export_report)
        self.export_btn.grid(row=0, column=0, sticky="w")
        self.export_btn.state(["disabled"])

        self.clear_btn = ttk.Button(btns, text="Clear", style="Export.TButton", command=self.clear_output)
        self.clear_btn.grid(row=0, column=1, sticky="e")

        right = ttk.Frame(main, style="Panel2.TFrame")
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=3)
        right.rowconfigure(4, weight=2)

        ttk.Label(right, text="📊  Analysis Results", style="PanelTitle2.TLabel").grid(row=0, column=0, sticky="w", padx=16, pady=(14, 10))

        self.risk_frame = tk.Frame(right, bg="#2a1020", highlightthickness=2, highlightbackground=NeonStyle.RED)
        self.risk_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        self.risk_frame.columnconfigure(0, weight=1)

        self.risk_label = tk.Label(
            self.risk_frame,
            text="Risk Level: —",
            bg="#2a1020",
            fg=NeonStyle.RED,
            font=("Segoe UI", 18, "bold"),
            pady=14
        )
        self.risk_label.grid(row=0, column=0, sticky="ew")

        self.findings = scrolledtext.ScrolledText(
            right,
            wrap=tk.WORD,
            bg="#070d1a",
            fg=NeonStyle.TEXT,
            insertbackground=NeonStyle.CYAN,
            relief="solid",
            bd=1,
            font=("Consolas", 10)
        )
        self.findings.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 10))

        ttk.Label(right, text="🛠  Remediation Recommendations", style="PanelTitle2.TLabel").grid(
            row=3, column=0, sticky="w", padx=16, pady=(0, 8)
        )

        self.recommendations = scrolledtext.ScrolledText(
            right,
            wrap=tk.WORD,
            bg="#070d1a",
            fg=NeonStyle.TEXT,
            insertbackground=NeonStyle.CYAN,
            relief="solid",
            bd=1,
            font=("Consolas", 10),
            height=8
        )
        self.recommendations.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 14))

        self.status = tk.Label(
            self.root,
            text="Ready",
            bg=NeonStyle.BG,
            fg=NeonStyle.MUTED,
            anchor="w",
            padx=18,
            pady=8
        )
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    def clear_output(self):
        self.output.delete("1.0", tk.END)
        self.findings.delete("1.0", tk.END)
        self.recommendations.delete("1.0", tk.END)
        self.risk_label.config(text="Risk Level: —")
        self.export_btn.state(["disabled"])
        self.last_output_text = ""
        self.last_vulns = []
        self.last_target = ""
        self.last_report = None
        self.status.config(text="Cleared")

    def start_scan(self):
        target = self.url_var.get().strip()
        if not target:
            messagebox.showerror("Missing URL", "Enter a target URL (e.g. https://local.test.com)")
            return

        self.clear_output()
        self.status.config(text=f"Scanning {target} …")
        self.scan_btn.state(["disabled"])
        self.export_btn.state(["disabled"])
        self.progress.start(12)

        t = threading.Thread(target=self._run_scan_thread, args=(target,), daemon=True)
        t.start()

    def _run_scan_thread(self, target):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        vulns = []
        report = None
        try:
            # Choose settings similar to crawler defaults
            max_depth = 3
            threads = 10
            timeout = 10

            # If you want enumeration like CLI, set this True.
            ENABLE_ENUM = True

            crawler = HTMLCrawler(
                target,
                max_depth=max_depth,
                threads=threads,
                timeout=timeout,
                patterns_file=None,     # will load default patterns.json next to crawler.py
                wordlists_file=None     # will load default wordlists.json next to crawler.py
            )

            if ENABLE_ENUM:
                found_dirs = crawler.enumerate_directories()
                base_paths = [d[0] for d in found_dirs if d[1] == 200]
                crawler.enumerate_files(base_paths if base_paths else None)

            crawler.crawl()
            report = crawler.generate_report(output_file=None)

            # Normalize severities for GUI
            vulns = report.get("vulnerabilities", [])
            for v in vulns:
                v["severity"] = severity_normalize(v.get("severity"))

        except Exception as e:
            print(f"\n[ERROR] {e}")
        finally:
            sys.stdout = old_stdout

        output_text = buffer.getvalue()
        self.root.after(0, self._finish_scan_ui, target, output_text, vulns, report)

    def _finish_scan_ui(self, target, output_text, vulns, report):
        self.progress.stop()
        self.scan_btn.state(["!disabled"])

        self.last_output_text = output_text
        self.last_vulns = vulns
        self.last_target = target
        self.last_report = report

        self.output.insert(tk.END, output_text)
        self.output.see(tk.END)

        self._render_findings(vulns)
        self._render_recommendations(vulns)

        self.export_btn.state(["!disabled"])
        self.status.config(text=f"Scan complete: {len(vulns)} finding(s)")

    def _render_findings(self, vulns):
        self.findings.delete("1.0", tk.END)

        label, color = risk_label_and_color(vulns)
        bg = "#2a1020" if label in ("CRITICAL", "HIGH") else "#2a2410" if label == "MEDIUM" else "#1a2a10" if label in ("LOW", "NONE") else "#1a1f2a"
        border = color

        self.risk_frame.config(bg=bg, highlightbackground=border)
        self.risk_label.config(text=f"Risk Level: {label}", bg=bg, fg=color)

        if not vulns:
            self.findings.insert(tk.END, "✅ No vulnerabilities reported by the crawler.\n")
            return

        groups = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for v in vulns:
            sev = v.get("severity", "Low")
            groups.get(sev, groups["Low"]).append(v)

        for sev in ["Critical", "High", "Medium", "Low"]:
            items = groups[sev]
            if not items:
                continue
            self.findings.insert(tk.END, f"\n=== {sev.upper()} ({len(items)}) ===\n")
            for i, v in enumerate(items, 1):
                vtype = v.get("type", "Unknown")
                name = v.get("name", "—")
                url = v.get("url", "—")
                line = v.get("line", 0)
                desc = v.get("description", "")
                snippet = v.get("code_snippet", "")

                self.findings.insert(
                    tk.END,
                    f"\n[{i}] {vtype} - {name}\n"
                    f"  URL: {url}\n"
                    f"  Line: {line}\n"
                    f"  Description: {desc}\n"
                )
                if snippet:
                    self.findings.insert(tk.END, f"  Evidence: {snippet}\n")

        self.findings.see(tk.END)

    def _render_recommendations(self, vulns):
        self.recommendations.delete("1.0", tk.END)
        self.recommendations.insert(tk.END, build_recommendations(vulns))
        self.recommendations.see(tk.END)

    def export_report(self):
        if not self.last_target:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"scan_report_{ts}.json"

        path = filedialog.asksaveasfilename(
            title="Export report",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON report", "*.json"), ("Text report", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            if path.lower().endswith(".txt"):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.last_output_text)
            else:
                report = self.last_report or {
                    "scan_info": {
                        "target": self.last_target,
                        "scan_time": datetime.now().isoformat()
                    },
                    "vulnerabilities": self.last_vulns
                }
                # Also include GUI fields for convenience
                report["_gui"] = {
                    "risk_level": risk_label_and_color(self.last_vulns)[0],
                    "findings_count": len(self.last_vulns)
                }
                report["_raw_output"] = self.last_output_text

                with open(path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)

            messagebox.showinfo("Exported", f"Saved report to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


def main():
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
