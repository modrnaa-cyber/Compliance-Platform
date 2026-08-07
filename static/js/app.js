console.log("app.js loaded");

window.addEventListener("DOMContentLoaded", () => {
    const runBtn = document.getElementById("runBtn");
    const targetInput = document.getElementById("target");
    const serviceTypeInput = document.getElementById("service_type");
    const statusMessage = document.getElementById("statusMessage");
    const exportPdfBtn = document.getElementById("exportPdfBtn");

    let pollTimer = null;

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function escapeHtml(value) {
        if (value === null || value === undefined || value === "") {
            return "-";
        }

        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function setText(id, value, fallback = "--") {
        const element = document.getElementById(id);
        if (!element) return;

        if (value === null || value === undefined || value === "") {
            element.textContent = fallback;
        } else {
            element.textContent = value;
        }
    }

    function updateRiskBadge(riskLevel) {
        const riskBadge = document.getElementById("riskBadge");
        if (!riskBadge) return;

        const level = riskLevel || "--";

        riskBadge.textContent = level;
        riskBadge.classList.remove("risk-low", "risk-medium", "risk-high");

        if (level === "Low") {
            riskBadge.classList.add("risk-low");
        } else if (level === "Medium") {
            riskBadge.classList.add("risk-medium");
        } else if (level === "High") {
            riskBadge.classList.add("risk-high");
        }
    }

    function renderComplianceGaps(result) {
        const tbody = document.getElementById("gapsTableBody");
        if (!tbody) return;

        tbody.innerHTML = "";

        const gaps = Array.isArray(result.compliance_gaps)
            ? result.compliance_gaps
            : [];

        if (!gaps.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="empty-row">No findings were returned.</td>
                </tr>
            `;
            return;
        }

        gaps.forEach((item) => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHtml(item.finding)}</td>
                <td>${escapeHtml(item.service)}</td>
                <td>${escapeHtml(item.risk)}</td>
                <td>${escapeHtml(item.cve)}</td>
                <td>${escapeHtml(item.nca_control)}</td>
                <td>${escapeHtml(item.source)}</td>
                <td>${escapeHtml(item.deduction)}</td>
                <td>${escapeHtml(item.remediation)}</td>
            `;

            tbody.appendChild(row);
        });
    }

    function renderNcaCoverage(result) {
        const ncaTbody = document.getElementById("ncaCoverageTableBody");
        if (!ncaTbody) return;

        ncaTbody.innerHTML = "";

        const coverage = Array.isArray(result.nca_coverage)
            ? result.nca_coverage
            : [];

        if (!coverage.length) {
            ncaTbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-row">No NCA coverage results returned.</td>
                </tr>
            `;
            return;
        }

        coverage.forEach((item) => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHtml(item.control_id)}</td>
                <td>${escapeHtml(item.domain)}</td>
                <td>${escapeHtml(item.control_name)}</td>
                <td>${escapeHtml(item.assessment_type)}</td>
                <td>${escapeHtml(item.status)}</td>
                <td>${escapeHtml(item.description)}</td>
            `;

            ncaTbody.appendChild(row);
        });
    }

   function renderDashboard(result) {
    result = result || {};

    setText(
        "finalScore",
        result.final_score !== undefined ? `${result.final_score}%` : "--"
    );

    setText("totalDeduction", result.total_deduction);
    setText("posture", result.posture);
    setText("totalFindings", result.total_findings);

    setText("summaryTarget", result.target);
    setText("summaryStatus", result.host_status);
    setText("summaryPosture", result.posture);
    setText("summaryFindings", result.total_findings);

    setText("sevCritical", result.severity_breakdown?.Critical ?? 0);
    setText("sevHigh", result.severity_breakdown?.High ?? 0);
    setText("sevMedium", result.severity_breakdown?.Medium ?? 0);
    setText("sevLow", result.severity_breakdown?.Low ?? 0);

    setText("srcInternal", result.source_breakdown?.Internal ?? 0);
    setText("srcNessus", result.source_breakdown?.OpenVAS ?? 0);
    setText("srcCorrelated", result.source_breakdown?.Correlated ?? 0);

    setText("summaryMode", result.mode_label ?? result.mode);
    setText("scannerState", "Completed");
    setText("lastAction", "Result rendered");
    setText("scanEngine", result.scan_engine);
    setText("scanDuration", `${result.scan_duration ?? 0}s`);
    setText("openPortsCount", result.total_open_ports ?? 0);

    updateRiskBadge(result.risk_level);

    const meta = result.nessus_meta || {};

    setText("nessusScanName", meta.scan_name ?? "Nmap Vulners");
    setText("nessusScanStatus", meta.message || meta.status || "--");
    setText("nessusConnected", meta.connected ? "Yes" : "No");
    setText("nessusUsed", meta.used ? "Yes" : "No");

    setText("modeType", result.mode);
    setText("dataSources", result.scan_engine);

    /*
      PDF report header fields
      These IDs must exist in index.html:
      printTarget, printMode, printDate
    */
    setText("printTarget", result.target);
    setText("printMode", result.mode_label ?? result.mode);

    const now = new Date();
    setText("printDate", now.toLocaleString());

    renderComplianceGaps(result);
    renderNcaCoverage(result);

    if (exportPdfBtn) {
        exportPdfBtn.disabled = false;
    }
}
    async function pollStatus(jobId) {
        try {
            const response = await fetch(`/api/assessment-status/${jobId}`);
            const data = await response.json();

            if (!response.ok || data.status !== "success") {
                throw new Error(data.message || "Polling failed");
            }

            const job = data.job || {};

            statusMessage.textContent = `${job.stage} - ${job.message} (${job.progress}%)`;
            setText("scannerState", job.status ?? "Running");
            setText("lastAction", job.stage ?? "--");

            if (job.status === "completed") {
                stopPolling();
                statusMessage.textContent = job.message || "Assessment completed successfully.";
                renderDashboard(job.result || {});
                runBtn.disabled = false;
                return;
            }

            if (job.status === "failed") {
                stopPolling();
                statusMessage.textContent = job.message || "Assessment failed.";
                setText("scannerState", "Failed");
                runBtn.disabled = false;
                return;
            }
        } catch (error) {
            stopPolling();
            statusMessage.textContent = error.message || "Polling failed.";
            setText("scannerState", "Failed");
            runBtn.disabled = false;
        }
    }

    runBtn.addEventListener("click", async () => {
        const target = targetInput.value.trim();
        const service_type = serviceTypeInput.value;

        if (!target) {
            statusMessage.textContent = "Please enter a target domain or IP.";
            return;
        }

        stopPolling();

        runBtn.disabled = true;

        if (exportPdfBtn) {
            exportPdfBtn.disabled = true;
        }

        statusMessage.textContent = "Creating assessment job...";
        setText("scannerState", "Queued");
        setText("lastAction", "Job creation");

        try {
            const response = await fetch("/api/start-assessment", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ target, service_type })
            });

            const data = await response.json();

            if (!response.ok || data.status !== "success") {
                throw new Error(data.message || "Failed to create assessment job.");
            }

            pollTimer = setInterval(() => pollStatus(data.job_id), 2000);
            pollStatus(data.job_id);
        } catch (error) {
            statusMessage.textContent = error.message || "Error while starting assessment.";
            setText("scannerState", "Failed");
            runBtn.disabled = false;
        }
    });

    if (exportPdfBtn) {
        exportPdfBtn.addEventListener("click", () => {
            const target =
                document.getElementById("summaryTarget")?.textContent || "Unknown Target";
            const mode =
                document.getElementById("summaryMode")?.textContent || "Unknown Mode";

            document.title = `GRC_Report_${target}_${mode}`.replaceAll(" ", "_");
            window.print();
        });
    }

    initCyberMouseTrail();
});

function initCyberMouseTrail() {
    const canvas = document.getElementById("cyberMouseTrail");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");

    let width = window.innerWidth;
    let height = window.innerHeight;

    const points = [];
    const maxPoints = 35;

    function resizeCanvas() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
    }

    window.addEventListener("resize", resizeCanvas);
    resizeCanvas();

    window.addEventListener("mousemove", (event) => {
        points.push({
            x: event.clientX,
            y: event.clientY,
            life: 1
        });

        if (points.length > maxPoints) {
            points.shift();
        }
    });

    function draw() {
        ctx.clearRect(0, 0, width, height);

        for (let i = 0; i < points.length - 1; i++) {
            const p1 = points[i];
            const p2 = points[i + 1];

            const opacity = Math.max(p1.life, 0);
            const lineWidth = 4 * opacity;

            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(0, 229, 255, ${opacity})`;
            ctx.lineWidth = lineWidth;
            ctx.shadowBlur = 18;
            ctx.shadowColor = "rgba(0, 229, 255, 0.9)";
            ctx.stroke();

            p1.life -= 0.035;
        }

        while (points.length && points[0].life <= 0) {
            points.shift();
        }

        requestAnimationFrame(draw);
    }

    draw();
}



async function loadIDSStatus() {
    try {
const res = await fetch('/api/ids-status');
        const d = await res.json();

        document.getElementById('ids-total').textContent    = d.total_alerts ?? '—';
        document.getElementById('ids-critical').textContent = d.critical ?? '—';
        document.getElementById('ids-high').textContent     = d.high ?? '—';
        document.getElementById('ids-medium').textContent   = d.medium ?? '—';
        document.getElementById('ids-topsig').textContent   = d.top_signature ?? '—';

        const badge = document.getElementById('ids-badge');
        if (d.connected) {
            badge.textContent = '● Live';
            badge.className = 'ids-badge ids-active';
        } else {
            badge.textContent = '● Offline';
            badge.className = 'ids-badge ids-offline';
        }

        const tbody = document.getElementById('ids-tbody');
        if (d.alerts && d.alerts.length > 0) {
            tbody.innerHTML = d.alerts.map(a => `
                <tr>
                    <td>${a.signature}</td>
                    <td>${['','🔴 Critical','🟠 High','🟡 Medium'][a.severity] || a.severity}</td>
                    <td>${a.src_ip}</td>
                    <td>${a.dest_ip}</td>
                    <td>${a.timestamp?.substring(0,19).replace('T',' ')}</td>
                    <td>${(a.nca_controls||[]).join(', ')}</td>
                </tr>`).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No alerts detected.</td></tr>';
        }
    } catch(e) {
        document.getElementById('ids-badge').textContent = '● Offline';
        document.getElementById('ids-badge').className = 'ids-badge ids-offline';
    }
}

// شغّله عند التحميل وكل 30 ثانية
loadIDSStatus();
setInterval(loadIDSStatus, 5000);