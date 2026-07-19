

from pathlib import Path
from collections import Counter, deque

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, Static, DataTable
from rich.text import Text
from rich.panel import Panel
from rich.align import Align

try:
    import pyfiglet
    BANNER = pyfiglet.figlet_format("CYBER SENTINEL", font="slant")
except ImportError:
    BANNER = "=== CYBER SENTINEL ==="

LOG_PATH = Path("live_predictions_log.csv")
LOG_COLUMNS = ["flow_number", "timestamp", "flow_id", "source_ip", "destination_ip",
               "predicted_label", "confidence"]
MAX_LOG_ROWS = 200
SUMMARY_INTERVAL = 100

LABEL_COLORS = {
    "BENIGN": "#00ff9f",
    "DoS Hulk": "#ff3860",
    "DoS slowloris": "#ff3860",
    "DoS Slowhttptest": "#ff3860",
    "DDoS": "#ff0055",
    "PortScan": "#ffb347",
    "FTP-Patator": "#00d9ff",
    "SSH-Patator": "#00d9ff",
    "Web Attack \u2013 Brute Force": "#ff00ff",
    "Web Attack \u2013 XSS": "#ff00ff",
    "Web Attack \u2013 Sql Injection": "#ff00ff",
    "Infiltration": "#ff0000",
    "Bot": "#ffea00",
}
DEFAULT_COLOR = "#ffffff"


def color_for(label: str) -> str:
    return LABEL_COLORS.get(label, DEFAULT_COLOR)


def read_new_rows(offset: int):
    """Read rows appended to the log since `offset`. Returns (rows, new_offset)."""
    if not LOG_PATH.exists():
        return [], offset

    import csv
    rows = []
    with open(LOG_PATH, newline="") as f:
        f.seek(offset)
        if offset == 0:
            reader = csv.DictReader(f)  # first read: consume header row automatically
        else:
            reader = csv.DictReader(f, fieldnames=LOG_COLUMNS)
        for row in reader:
            if row.get("flow_number") == "flow_number":
                continue  # safety: skip stray header if seen again
            rows.append(row)
        new_offset = f.tell()
    return rows, new_offset


class SplashScreen(Screen):
    """Shown until the first flow prediction arrives in the log file."""

    def compose(self) -> ComposeResult:
        yield Container(
            Static(BANNER, id="banner"),
            Static(
                "AI-Powered Cybersecurity Threat Detection System\n\n"
                "Real-time network flow classification using a Random Forest\n"
                "model trained on CIC-IDS-2017 \u2014 detects DoS, PortScan,\n"
                "Web Attacks, Infiltration, Bots and more.\n\n"
                "Repo: github.com/harikishore2004/ThreatDetectionSystem",
                id="description",
            ),
            Static("\u25cf WAITING FOR LIVE STREAM TO START...", id="status"),
            id="splash-container",
        )

    def on_mount(self) -> None:
        self._blink_on = True
        self._triggered = False
        self.set_interval(0.6, self.blink_status)
        self._stream_timer = self.set_interval(0.5, self.check_stream)

    def blink_status(self) -> None:
        status = self.query_one("#status", Static)
        self._blink_on = not self._blink_on
        status.styles.opacity = 1.0 if self._blink_on else 0.3

    def check_stream(self) -> None:
        if self._triggered:
            return
        rows, _ = read_new_rows(0)
        if rows:
            self._triggered = True
            self._stream_timer.stop()
            self.app.push_screen(DashboardScreen())


class LabelBarChart(Static):
    """Live bar chart of predicted label counts."""

    def __init__(self) -> None:
        super().__init__(id="chart")
        self.counts: Counter = Counter()

    def update_counts(self, counts: Counter) -> None:
        self.counts = counts
        self.refresh()

    def render(self):
        if not self.counts:
            return Align.center(Text("No data yet..."), vertical="middle")

        total = sum(self.counts.values())
        max_count = max(self.counts.values())
        lines = []
        for label, count in self.counts.most_common():
            bar_len = int((count / max_count) * 28) if max_count else 0
            bar = "\u2588" * bar_len
            pct = (count / total) * 100 if total else 0
            color = color_for(label)
            line = Text()
            line.append(f"{label:<26}", style=color)
            line.append(f" {bar} ", style=color)
            line.append(f"{count} ({pct:.1f}%)", style="dim")
            lines.append(line)

        body = Text("\n").join(lines)
        return Panel(body, title="Label Distribution", border_style="bright_magenta")


class DashboardScreen(Screen):
    """Main live monitoring dashboard."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-body"):
            with Vertical(id="left-pane"):
                yield Static("LIVE FLOW LOG", id="log-title")
                yield DataTable(id="log-table")
            with Vertical(id="right-pane"):
                yield Static("THREAT DISTRIBUTION", id="chart-title")
                yield LabelBarChart()
        yield Static("Waiting for flows...", id="summary-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#log-table", DataTable)
        table.add_columns("Time", "Flow ID", "Src IP", "Dst IP", "Prediction", "Confidence")
        table.zebra_stripes = True
        table.cursor_type = "row"

        self._offset = 0
        self._counts = Counter()
        self._total = 0
        self._last_milestone = 0
        self._row_keys = deque()

        self.set_interval(0.5, self.poll_log)

    def poll_log(self) -> None:
        rows, new_offset = read_new_rows(self._offset)
        self._offset = new_offset
        if not rows:
            return

        table = self.query_one("#log-table", DataTable)
        chart = self.query_one(LabelBarChart)

        for row in rows:
            label = row.get("predicted_label", "UNKNOWN") or "UNKNOWN"
            conf_raw = row.get("confidence", "")
            try:
                conf_display = f"{float(conf_raw):.2f}"
            except (TypeError, ValueError):
                conf_display = ""
            color = color_for(label)

            key = table.add_row(
                row.get("timestamp", ""),
                (row.get("flow_id", "") or "")[:20],
                row.get("source_ip", ""),
                row.get("destination_ip", ""),
                Text(label, style=color),
                conf_display,
            )
            self._row_keys.append(key)
            if len(self._row_keys) > MAX_LOG_ROWS:
                old_key = self._row_keys.popleft()
                try:
                    table.remove_row(old_key)
                except Exception:
                    pass

            self._counts[label] += 1
            self._total += 1

        table.scroll_end(animate=False)
        chart.update_counts(self._counts)

        summary = self.query_one("#summary-bar", Static)
        top = self._counts.most_common(3)
        top_str = "  |  ".join(f"{l}: {c}" for l, c in top)
        summary.update(f"TOTAL FLOWS: {self._total}   \u2502   TOP: {top_str}")

        if self._total - self._last_milestone >= SUMMARY_INTERVAL:
            self._last_milestone = (self._total // SUMMARY_INTERVAL) * SUMMARY_INTERVAL
            self.notify(
                f"Milestone: {self._total} flows processed \u2014 {dict(self._counts)}",
                title="Summary",
                timeout=6,
            )


class CyberSentinelApp(App):
    CSS = """
    Screen {
        background: #0a0e14;
        color: #e6e6e6;
    }

    #splash-container {
        align: center middle;
        height: 100%;
        width: 100%;
    }

    #banner {
        color: #00ff9f;
        text-align: center;
        width: 100%;
        text-style: bold;
    }

    #description {
        color: #00d9ff;
        text-align: center;
        margin-top: 2;
        width: 100%;
    }

    #status {
        color: #ff3860;
        text-align: center;
        margin-top: 3;
        text-style: bold;
        width: 100%;
    }

    #main-body {
        height: 1fr;
    }

    #left-pane {
        width: 62%;
        border: round #00d9ff;
        padding: 0 1;
    }

    #right-pane {
        width: 38%;
        border: round #ff00ff;
        padding: 0 1;
    }

    #log-title, #chart-title {
        color: #00ff9f;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
        width: 100%;
    }

    #summary-bar {
        height: 3;
        background: #131820;
        color: #ffea00;
        text-style: bold;
        content-align: center middle;
        border: round #ffea00;
    }

    DataTable {
        background: #0a0e14;
        height: 1fr;
    }
    """

    TITLE = "Cyber Sentinel \u2014 Threat Detection"

    def on_mount(self) -> None:
        self.push_screen(SplashScreen())


if __name__ == "__main__":
    CyberSentinelApp().run()