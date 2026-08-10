import json
import os
from datetime import datetime
from html import escape


def build_current_states(events):
    """
    Reconstruct the latest known state of every
    monitored protocol/port combination.
    """

    states = {}

    for event in events:

        protocol = event.get("protocol")
        port = event.get("port")

        if protocol is None or port is None:
            continue

        key = (protocol, port)

        status = event.get("status")

        if status is None:
            status = event.get("new_status")

        if status is None:
            continue

        states[key] = {
            "protocol": protocol,
            "port": port,
            "service": event.get(
                "service",
                "Unknown"
            ),
            "status": status,
            "banner": event.get(
                "banner"
            )
        }

    return states


def get_status_class(status):
    """
    Return CSS class according to port state.
    """

    status = str(status).upper()

    if status == "OPEN":
        return "status-open"

    if status == "CLOSED":
        return "status-closed"

    if status == "NO_RESPONSE":
        return "status-warning"

    return "status-unknown"


def get_status_badge(status):
    """
    Generate a styled status badge.
    """

    css_class = get_status_class(status)

    return (
        f'<span class="status-badge {css_class}">'
        f'{escape(str(status))}'
        f'</span>'
    )


def generate_report(host, ports, events):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # =========================================================
    # CURRENT STATES
    # =========================================================

    current_states = build_current_states(
        events
    )

    # =========================================================
    # STATISTICS
    # =========================================================

    initial_events = sum(
        1
        for event in events
        if event.get("type") == "INITIAL_STATE"
    )

    change_events = sum(
        1
        for event in events
        if event.get("type") == "PORT_CHANGE"
    )

    alert_events = sum(
        1
        for event in events
        if event.get("type") == "ALERT"
    )

    open_count = sum(
        1
        for state in current_states.values()
        if state["status"] == "OPEN"
    )

    closed_count = sum(
        1
        for state in current_states.values()
        if state["status"] == "CLOSED"
    )

    warning_count = sum(
        1
        for state in current_states.values()
        if state["status"] == "NO_RESPONSE"
    )

    # =========================================================
    # CHANGE COUNTS
    # =========================================================

    change_counts = {}

    for event in events:

        if event.get("type") != "PORT_CHANGE":
            continue

        key = (
            event.get("protocol"),
            event.get("port")
        )

        change_counts[key] = (
            change_counts.get(key, 0) + 1
        )

    # =========================================================
    # JSON REPORT
    # =========================================================

    json_states = []

    for key, state in sorted(
        current_states.items(),
        key=lambda item: (
            item[0][0],
            item[0][1]
        )
    ):

        json_states.append({
            "protocol": state["protocol"],
            "port": state["port"],
            "service": state["service"],
            "status": state["status"],
            "changes": change_counts.get(
                key,
                0
            ),
            "banner": state["banner"]
        })

    report = {
        "generated_at": generated_at,
        "host": host,
        "monitored_ports": ports,
        "statistics": {
            "total_events": len(events),
            "initial_states": initial_events,
            "port_changes": change_events,
            "alerts": alert_events,
            "open_ports": open_count,
            "closed_ports": closed_count,
            "no_response": warning_count
        },
        "current_states": json_states,
        "events": events
    }

    with open(
        "reports/report.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    # =========================================================
    # CURRENT PORT TABLE
    # =========================================================

    port_rows = ""

    for key, state in sorted(
        current_states.items(),
        key=lambda item: (
            item[0][0],
            item[0][1]
        )
    ):

        protocol = escape(
            str(state["protocol"])
        )

        port = escape(
            str(state["port"])
        )

        service = escape(
            str(state["service"])
        )

        status = state["status"]

        badge = get_status_badge(
            status
        )

        changes = change_counts.get(
            key,
            0
        )

        banner = state.get(
            "banner"
        )

        if banner:

            banner_html = f"""
            <details class="banner-details">
                <summary>View banner</summary>
                <code>{escape(str(banner))}</code>
            </details>
            """

        else:

            banner_html = (
                '<span class="muted">—</span>'
            )

        port_rows += f"""
        <tr>
            <td class="port-number">
                {port}
            </td>

            <td>
                <span class="protocol">
                    {protocol}
                </span>
            </td>

            <td>
                {service}
            </td>

            <td>
                {badge}
            </td>

            <td>
                {changes}
            </td>

            <td>
                {banner_html}
            </td>
        </tr>
        """

    if not port_rows:

        port_rows = """
        <tr>
            <td colspan="6" class="empty">
                No port state data available.
            </td>
        </tr>
        """

    # =========================================================
    # SECURITY ALERTS
    # =========================================================

    alert_rows = ""

    for event in events:

        if event.get("type") != "ALERT":
            continue

        event_time = escape(
            str(event.get("time", ""))
        )

        protocol = escape(
            str(event.get("protocol", ""))
        )

        port = escape(
            str(event.get("port", ""))
        )

        service = escape(
            str(event.get("service", "Unknown"))
        )

        old_status = event.get(
            "old_status"
        )

        new_status = event.get(
            "new_status"
        )

        status = event.get(
            "status"
        )

        if old_status and new_status:

            transition = (
                f"{escape(str(old_status))}"
                f" → "
                f"{escape(str(new_status))}"
            )

        elif status:

            transition = escape(
                str(status)
            )

        else:

            transition = "Unexpected state"

        alert_rows += f"""
        <div class="alert-item">

            <div class="alert-icon">
                !
            </div>

            <div class="alert-content">

                <div class="alert-title">
                    Unexpected port state
                </div>

                <div class="alert-description">
                    {protocol}/{port}
                    &nbsp;·&nbsp;
                    {service}
                    &nbsp;·&nbsp;
                    <strong>{transition}</strong>
                </div>

                <div class="alert-time">
                    {event_time}
                </div>

            </div>

        </div>
        """

    if not alert_rows:

        alert_rows = """
        <div class="no-alerts">
            <span class="check-icon">✓</span>
            No security alerts detected.
        </div>
        """

    # =========================================================
    # EVENT HISTORY
    # =========================================================

    event_rows = ""

    # Display newest first
    reversed_events = list(
        reversed(events)
    )

    for event in reversed_events:

        event_time = escape(
            str(event.get("time", ""))
        )

        event_type = str(
            event.get(
                "type",
                ""
            )
        )

        event_type_html = escape(
            event_type
        )

        protocol = escape(
            str(
                event.get(
                    "protocol",
                    "-"
                )
            )
        )

        port = escape(
            str(
                event.get(
                    "port",
                    "-"
                )
            )
        )

        service = escape(
            str(
                event.get(
                    "service",
                    "-"
                )
            )
        )

        old_status = event.get(
            "old_status"
        )

        new_status = event.get(
            "new_status"
        )

        status = event.get(
            "status"
        )

        if old_status and new_status:

            status_text = (
                f"{old_status} → {new_status}"
            )

        elif status:

            status_text = str(status)

        else:

            status_text = "-"

        status_html = escape(
            status_text
        )

        event_class = (
            event_type.lower()
            .replace("_", "-")
        )

        event_rows += f"""
        <tr>

            <td class="event-time">
                {event_time}
            </td>

            <td>
                <span class="event-badge {event_class}">
                    {event_type_html}
                </span>
            </td>

            <td>
                {protocol}
            </td>

            <td class="port-number">
                {port}
            </td>

            <td>
                {service}
            </td>

            <td>
                {status_html}
            </td>

        </tr>
        """

    if not event_rows:

        event_rows = """
        <tr>
            <td colspan="6" class="empty">
                No monitoring events recorded.
            </td>
        </tr>
        """

    # =========================================================
    # HTML REPORT
    # =========================================================

    html = f"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
    Port Monitor Report
</title>

<style>

:root {{
    --bg: #0b1120;
    --panel: #111827;
    --panel-light: #172033;
    --border: #243044;

    --text: #e5e7eb;
    --muted: #94a3b8;

    --blue: #3b82f6;
    --blue-soft: rgba(59, 130, 246, 0.12);

    --green: #22c55e;
    --green-soft: rgba(34, 197, 94, 0.12);

    --red: #ef4444;
    --red-soft: rgba(239, 68, 68, 0.12);

    --amber: #f59e0b;
    --amber-soft: rgba(245, 158, 11, 0.12);

    --shadow:
        0 8px 25px rgba(0, 0, 0, 0.20);
}}

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    background:
        var(--bg);

    color:
        var(--text);

    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;

    line-height: 1.5;
}}

.container {{

    width: min(
        1400px,
        calc(100% - 40px)
    );

    margin: 0 auto;

    padding: 35px 0 50px;
}}

/* ==========================================
   HEADER
   ========================================== */

.header {{

    display: flex;

    justify-content:
        space-between;

    align-items:
        center;

    gap: 20px;

    margin-bottom: 28px;
}}

.brand {{

    display: flex;

    align-items: center;

    gap: 14px;
}}

.logo {{

    width: 44px;
    height: 44px;

    display: flex;

    align-items: center;
    justify-content: center;

    background:
        var(--blue-soft);

    border:
        1px solid
        rgba(59, 130, 246, 0.35);

    border-radius: 10px;

    color:
        var(--blue);

    font-weight: 800;

    font-size: 20px;
}}

.title h1 {{

    margin: 0;

    font-size: 23px;

    letter-spacing:
        -0.4px;
}}

.title p {{

    margin: 2px 0 0;

    color:
        var(--muted);

    font-size: 13px;
}}

.version {{

    padding:
        6px 10px;

    border:
        1px solid
        var(--border);

    border-radius: 6px;

    color:
        var(--muted);

    font-size: 12px;

    font-family:
        monospace;
}}

/* ==========================================
   TARGET PANEL
   ========================================== */

.target-panel {{

    display: grid;

    grid-template-columns:
        2fr 1fr 1fr;

    gap: 1px;

    background:
        var(--border);

    border:
        1px solid
        var(--border);

    border-radius: 10px;

    overflow: hidden;

    margin-bottom: 22px;

    box-shadow:
        var(--shadow);
}}

.target-item {{

    background:
        var(--panel);

    padding:
        18px 20px;
}}

.target-label {{

    color:
        var(--muted);

    font-size: 15px;

    text-transform:
        uppercase;

    letter-spacing:
        0.8px;

    margin-bottom: 5px;
}}

.target-value {{

    font-size: 15px;

    font-weight: 600;

    word-break:
        break-word;
}}

.mono {{

    font-family:
        "Cascadia Code",
        "Consolas",
        monospace;
}}

/* ==========================================
   SUMMARY CARDS
   ========================================== */

.cards {{

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 16px;

    margin-bottom: 28px;
}}

.card {{

    background:
        var(--panel);

    border:
        1px solid
        var(--border);

    border-radius:
        10px;

    padding:
        20px;

    box-shadow:
        var(--shadow);

    position:
        relative;

    overflow:
        hidden;
}}

.card::before {{

    content: "";

    position:
        absolute;

    left: 0;
    top: 0;

    width: 3px;
    height: 100%;

    background:
        var(--blue);
}}

.card.green::before {{
    background: var(--green);
}}

.card.red::before {{
    background: var(--red);
}}

.card.amber::before {{
    background: var(--amber);
}}

.card-label {{

    color:
        var(--muted);

    font-size: 12px;

    margin-bottom: 7px;
}}

.card-value {{

    font-size: 27px;

    font-weight: 700;
}}

.card-subtitle {{

    color:
        var(--muted);

    font-size: 15px;

    margin-top: 5px;
}}

/* ==========================================
   SECTION
   ========================================== */

.section {{

    margin-bottom: 28px;
}}

.section-header {{

    display: flex;

    justify-content:
        space-between;

    align-items:
        center;

    margin-bottom: 12px;
}}

.section-title {{

    margin: 0;

    font-size: 16px;

    font-weight: 650;
}}

.section-count {{

    color:
        var(--muted);

    font-size: 12px;
}}

/* ==========================================
   TABLE
   ========================================== */

.table-wrapper {{

    overflow-x:
        auto;

    background:
        var(--panel);

    border:
        1px solid
        var(--border);

    border-radius:
        10px;

    box-shadow:
        var(--shadow);
}}

table {{

    width: 100%;

    border-collapse:
        collapse;

    min-width:
        800px;
}}

th {{

    padding:
        13px 16px;

    background:
        var(--panel-light);

    color:
        var(--muted);

    font-size:
        11px;

    text-transform:
        uppercase;

    letter-spacing:
        0.6px;

    text-align:
        left;

    font-weight:
        600;

    border-bottom:
        1px solid
        var(--border);
}}

td {{

    padding:
        14px 16px;

    border-bottom:
        1px solid
        rgba(36, 48, 68, 0.65);

    font-size:
        13px;
}}

tbody tr:last-child td {{
    border-bottom: none;
}}

tbody tr:hover {{
    background:
        rgba(255,255,255,0.02);
}}

.port-number {{

    font-family:
        "Cascadia Code",
        "Consolas",
        monospace;

    font-weight:
        600;
}}

.protocol {{

    color:
        var(--blue);

    font-size:
        11px;

    font-weight:
        700;
}}

.status-badge {{

    display:
        inline-flex;

    align-items:
        center;

    gap: 6px;

    padding:
        4px 9px;

    border-radius:
        5px;

    font-size:
        11px;

    font-weight:
        700;
}}

.status-badge::before {{

    content: "";

    width: 6px;
    height: 6px;

    border-radius:
        50%;
}}

.status-open {{

    color:
        var(--green);

    background:
        var(--green-soft);
}}

.status-open::before {{
    background: var(--green);
}}

.status-closed {{

    color:
        var(--muted);

    background:
        rgba(148, 163, 184, 0.10);
}}

.status-closed::before {{
    background: var(--muted);
}}

.status-warning {{

    color:
        var(--amber);

    background:
        var(--amber-soft);
}}

.status-warning::before {{
    background: var(--amber);
}}

.status-unknown {{

    color:
        var(--muted);

    background:
        rgba(148, 163, 184, 0.10);
}}

.status-unknown::before {{
    background: var(--muted);
}}

.muted {{
    color:
        var(--muted);
}}

/* ==========================================
   BANNER
   ========================================== */

.banner-details summary {{

    color:
        var(--blue);

    cursor:
        pointer;

    font-size:
        11px;
}}

.banner-details code {{

    display:
        block;

    margin-top:
        8px;

    max-width:
        350px;

    padding:
        8px;

    background:
        #0a0f1c;

    border:
        1px solid
        var(--border);

    border-radius:
        5px;

    color:
        var(--muted);

    font-size:
        15px;

    white-space:
        pre-wrap;

    word-break:
        break-word;
}}

/* ==========================================
   ALERTS
   ========================================== */

.alert-container {{

    background:
        var(--panel);

    border:
        1px solid
        var(--border);

    border-radius:
        10px;

    overflow:
        hidden;

    box-shadow:
        var(--shadow);
}}

.alert-item {{

    display:
        flex;

    gap:
        14px;

    padding:
        16px 18px;

    border-bottom:
        1px solid
        var(--border);

    background:
        rgba(239, 68, 68, 0.035);
}}

.alert-item:last-child {{
    border-bottom: none;
}}

.alert-icon {{

    flex:
        0 0 auto;

    width:
        28px;

    height:
        28px;

    display:
        flex;

    align-items:
        center;

    justify-content:
        center;

    border-radius:
        50%;

    background:
        var(--red-soft);

    color:
        var(--red);

    font-weight:
        800;

    font-size:
        13px;
}}

.alert-content {{
    min-width: 0;
}}

.alert-title {{

    color:
        var(--text);

    font-size:
        13px;

    font-weight:
        650;
}}

.alert-description {{

    margin-top:
        2px;

    color:
        var(--muted);

    font-size:
        12px;
}}

.alert-description strong {{
    color: var(--red);
}}

.alert-time {{

    margin-top:
        5px;

    color:
        #64748b;

    font-size:
        10px;

    font-family:
        monospace;
}}

.no-alerts {{

    padding:
        20px;

    color:
        var(--green);

    font-size:
        13px;

    display:
        flex;

    align-items:
        center;

    gap:
        10px;
}}

.check-icon {{

    display:
        inline-flex;

    width:
        24px;

    height:
        24px;

    align-items:
        center;

    justify-content:
        center;

    border-radius:
        50%;

    background:
        var(--green-soft);
}}

/* ==========================================
   EVENT BADGES
   ========================================== */

.event-badge {{

    display:
        inline-block;

    padding:
        4px 8px;

    border-radius:
        5px;

    font-size:
        10px;

    font-weight:
        700;

    letter-spacing:
        0.2px;
}}

.initial-state {{

    color:
        var(--blue);

    background:
        var(--blue-soft);
}}

.port-change {{

    color:
        var(--amber);

    background:
        var(--amber-soft);
}}

.alert {{

    color:
        var(--red);

    background:
        var(--red-soft);
}}

.event-time {{

    white-space:
        nowrap;

    color:
        var(--muted);

    font-family:
        monospace;

    font-size:
        11px;
}}

.empty {{

    text-align:
        center;

    color:
        var(--muted);

    padding:
        30px;
}}

/* ==========================================
   FOOTER
   ========================================== */

.footer {{

    margin-top:
        30px;

    padding-top:
        18px;

    border-top:
        1px solid
        var(--border);

    color:
        #64748b;

    font-size:
        11px;

    display:
        flex;

    justify-content:
        space-between;

    gap:
        15px;

    flex-wrap:
        wrap;
}}

/* ==========================================
   RESPONSIVE
   ========================================== */

@media (max-width: 900px) {{

    .cards {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

    .target-panel {{
        grid-template-columns:
            1fr;
    }}

    .header {{
        align-items:
            flex-start;
    }}

}}

@media (max-width: 600px) {{

    .container {{
        width:
            min(
                100% - 24px,
                1400px
            );

        padding-top:
            22px;
    }}

    .cards {{
        grid-template-columns:
            1fr;
    }}

    .header {{
        flex-direction:
            column;
    }}

}}

</style>

</head>

<body>

<div class="container">

    <!-- =======================================
         HEADER
         ======================================= -->

    <header class="header">

        <div class="brand">

            <div class="logo">
                PM
            </div>

            <div class="title">

                <h1>
                    Port Monitor
                </h1>

                <p>
                    Network Security Monitoring Report
                </p>

            </div>

        </div>

        <div class="version">
            v1.0.0
        </div>

    </header>


    <!-- =======================================
         TARGET INFORMATION
         ======================================= -->

    <div class="target-panel">

        <div class="target-item">

            <div class="target-label">
                Target
            </div>

            <div class="target-value mono">
                {escape(str(host))}
            </div>

        </div>

        <div class="target-item">

            <div class="target-label">
                Monitored Ports
            </div>

            <div class="target-value">
                {len(ports)}
            </div>

        </div>

        <div class="target-item">

            <div class="target-label">
                Generated
            </div>

            <div class="target-value">
                {escape(generated_at)}
            </div>

        </div>

    </div>


    <!-- =======================================
         SUMMARY
         ======================================= -->

    <div class="cards">

        <div class="card">

            <div class="card-label">
                Total Events
            </div>

            <div class="card-value">
                {len(events)}
            </div>

            <div class="card-subtitle">
                Recorded monitoring events
            </div>

        </div>


        <div class="card amber">

            <div class="card-label">
                Port Changes
            </div>

            <div class="card-value">
                {change_events}
            </div>

            <div class="card-subtitle">
                Detected state transitions
            </div>

        </div>


        <div class="card red">

            <div class="card-label">
                Security Alerts
            </div>

            <div class="card-value">
                {alert_events}
            </div>

            <div class="card-subtitle">
                Unexpected states
            </div>

        </div>


        <div class="card green">

            <div class="card-label">
                Open Ports
            </div>

            <div class="card-value">
                {open_count}
            </div>

            <div class="card-subtitle">
                Current known state
            </div>

        </div>

    </div>


    <!-- =======================================
         CURRENT PORT STATUS
         ======================================= -->

    <section class="section">

        <div class="section-header">

            <h2 class="section-title">
                Current Port Status
            </h2>

            <span class="section-count">
                {len(current_states)} observed
            </span>

        </div>


        <div class="table-wrapper">

            <table>

                <thead>

                    <tr>

                        <th>
                            Port
                        </th>

                        <th>
                            Protocol
                        </th>

                        <th>
                            Service
                        </th>

                        <th>
                            Status
                        </th>

                        <th>
                            Changes
                        </th>

                        <th>
                            Banner
                        </th>

                    </tr>

                </thead>

                <tbody>

                    {port_rows}

                </tbody>

            </table>

        </div>

    </section>


    <!-- =======================================
         SECURITY ALERTS
         ======================================= -->

    <section class="section">

        <div class="section-header">

            <h2 class="section-title">
                Security Alerts
            </h2>

            <span class="section-count">
                {alert_events} detected
            </span>

        </div>

        <div class="alert-container">

            {alert_rows}

        </div>

    </section>


    <!-- =======================================
         EVENT HISTORY
         ======================================= -->

    <section class="section">

        <div class="section-header">

            <h2 class="section-title">
                Event History
            </h2>

            <span class="section-count">
                {len(events)} events
            </span>

        </div>

        <div class="table-wrapper">

            <table>

                <thead>

                    <tr>

                        <th>
                            Time
                        </th>

                        <th>
                            Event
                        </th>

                        <th>
                            Protocol
                        </th>

                        <th>
                            Port
                        </th>

                        <th>
                            Service
                        </th>

                        <th>
                            Status
                        </th>

                    </tr>

                </thead>

                <tbody>

                    {event_rows}

                </tbody>

            </table>

        </div>

    </section>


    <!-- =======================================
         FOOTER
         ======================================= -->

    <footer class="footer">

        <span>
            Port Monitor v1.0.0
        </span>

        <span>
            Generated locally · No external resources
        </span>

    </footer>

</div>

</body>

</html>
"""

    # =========================================================
    # WRITE HTML
    # =========================================================

    with open(
        "reports/report.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print()
    print("[+] Reports generated:")
    print("    reports/report.json")
    print("    reports/report.html")