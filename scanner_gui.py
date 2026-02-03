import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import sys
import io
import json
from datetime import datetime

# Your scanner class
from HTMLSide import WebVulnerabilityScanner


class GUIScanner(WebVulnerabilityScanner):
    """
    Subclass your scanner so we can capture the vulnerabilities list that
    display_results() receives, while keeping the original printing behavior.
    """
    def __init__(self, target_url):
        super().__init__(target_url)
        self.last_vulnerabilities = []

    def display_results(self, vulnerabilities):
        self.last_vulnerabilities = vulnerabilities[:] if vulnerabilities else []
        # Call original behavior (prints report)
        super().display_results(vulnerabilities)


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


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Vulnerability Analyzer")
        self.root.geometry("1200x720")
        self.root.configure(bg=NeonStyle.BG)

        self.last_output_text = ""
        self.last_vulns = []
        self.last_target = ""

        self._build_styles()
        self._build_layout()

    def _build_styles(self):
        style = ttk.Style()
        # Use "clam" so we can theme ttk elements
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
        # Header
        header = ttk.Frame(self.root, style="Neon.TFrame")
        header.pack(fill=tk.X, padx=18, pady=(18, 10))

        ttk.Label(header, text="Web Vulnerability Analyzer", style="Title.TLabel").pack(anchor="center")
        ttk.Label(
            header,
            text="Static analysis for forms + client-side script patterns (scanner output + exportable report)",
            style="SubTitle.TLabel"
        ).pack(anchor="center", pady=(6, 0))

        # Main split
        main = ttk.Frame(self.root, style="Neon.TFrame")
        main.pack(fill=tk.BOTH, expand=True, padx=18, pady=12)

        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        # Left: Input panel
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

        # Console output (like your terminal report)
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

        # Progress + buttons
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

        # Right: Results panel
        right = ttk.Frame(main, style="Panel2.TFrame")
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
        right.columnconfigure(0, weight=1)

        # Make findings + recommendations both expand
        right.rowconfigure(2, weight=3)  # findings
        right.rowconfigure(4, weight=2)  # recommendations

        ttk.Label(right, text="📊  Analysis Results", style="PanelTitle2.TLabel").grid(row=0, column=0, sticky="w", padx=16, pady=(14, 10))

        # Risk banner
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

        # Findings list
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

        # Recommendations panel title
        ttk.Label(right, text="🛠  Remediation Recommendations", style="PanelTitle2.TLabel").grid(
            row=3, column=0, sticky="w", padx=16, pady=(0, 8)
        )

        # Recommendations box
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

        # Status bar
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

        # Start indeterminate progress animation
        self.progress.start(12)

        t = threading.Thread(target=self._run_scan_thread, args=(target,), daemon=True)
        t.start()

    def _run_scan_thread(self, target):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        vulns = []
        try:
            scanner = GUIScanner(target)
            scanner.scan()
            vulns = scanner.last_vulnerabilities
        except Exception as e:
            print(f"\n[ERROR] {e}")
        finally:
            sys.stdout = old_stdout

        output_text = buffer.getvalue()
        self.root.after(0, self._finish_scan_ui, target, output_text, vulns)

    def _finish_scan_ui(self, target, output_text, vulns):
        self.progress.stop()
        self.scan_btn.state(["!disabled"])

        self.last_output_text = output_text
        self.last_vulns = vulns
        self.last_target = target

        # Left console
        self.output.insert(tk.END, output_text)
        self.output.see(tk.END)

        # Right findings summary
        self._render_findings(vulns)

        # Bottom-right recommendations
        self._render_recommendations(output_text, vulns)

        self.export_btn.state(["!disabled"])
        self.status.config(text=f"Scan complete: {len(vulns)} finding(s)")

    def _render_findings(self, vulns):
        self.findings.delete("1.0", tk.END)

        label, color = risk_label_and_color(vulns)
        # Update risk banner colors
        bg = "#2a1020" if label in ("CRITICAL", "HIGH") else "#2a2410" if label == "MEDIUM" else "#1a2a10" if label in ("LOW", "NONE") else "#1a1f2a"
        border = color

        self.risk_frame.config(bg=bg, highlightbackground=border)
        self.risk_label.config(text=f"Risk Level: {label}", bg=bg, fg=color)

        if not vulns:
            self.findings.insert(tk.END, "✅ No vulnerabilities reported by the scanner.\n")
            return

        # Group by severity
        groups = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for v in vulns:
            groups.get(v.get("severity", "Low"), groups["Low"]).append(v)

        for sev in ["Critical", "High", "Medium", "Low"]:
            items = groups[sev]
            if not items:
                continue
            self.findings.insert(tk.END, f"\n=== {sev.upper()} ({len(items)}) ===\n")
            for i, v in enumerate(items, 1):
                t = v.get("type", "Unknown")
                field = v.get("field", "—")
                desc = v.get("description", "")
                self.findings.insert(tk.END, f"\n[{i}] {t}\n  Field: {field}\n  Description: {desc}\n")

        self.findings.see(tk.END)

    def _render_recommendations(self, output_text, vulns):
        """
        Extract the scanner's printed recommendations section (if present),
        and show it in the bottom-right box.
        """
        self.recommendations.delete("1.0", tk.END)

        lines = output_text.splitlines()
        start = None
        for i, line in enumerate(lines):
            if "RECOMMENDATIONS" in line:
                start = i
                break

        if start is not None:
            # Keep only the recommendation lines after the header separators
            # (Your scanner prints numbered items below the RECOMMENDATIONS section.)
            extracted = "\n".join(lines[start:]).strip()
            self.recommendations.insert(tk.END, extracted)
            self.recommendations.see(tk.END)
            return

        # Fallbacks (in case scanner output format changes)
        if not vulns:
            self.recommendations.insert(
                tk.END,
                "✅ No issues detected.\n\nKeep these controls in place:\n"
                "• Server-side validation\n"
                "• CSRF tokens (and SameSite cookies)\n"
                "• Safe DOM APIs (textContent) instead of innerHTML\n"
            )
        else:
            self.recommendations.insert(
                tk.END,
                "General remediation guidance:\n"
                "1) Implement server-side validation for all fields\n"
                "2) Add sanitization / output encoding for user-controlled content\n"
                "3) Use CSRF tokens + Origin/Referer validation where appropriate\n"
                "4) Prefer textContent / createTextNode over innerHTML\n"
                "5) Add strict input constraints (maxlength, patterns, min/max)\n"
            )

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
                report = {
                    "target": self.last_target,
                    "timestamp": datetime.now().isoformat(),
                    "risk_level": risk_label_and_color(self.last_vulns)[0],
                    "findings_count": len(self.last_vulns),
                    "findings": self.last_vulns,
                    "raw_output": self.last_output_text,
                }
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
