const form = document.getElementById("assessment-form");
const formStatus = document.getElementById("form-status");
const resultsSection = document.getElementById("results-section");
const finalScore = document.getElementById("final-score");
const totalDeduction = document.getElementById("total-deduction");
const posture = document.getElementById("posture");
const totalFindings = document.getElementById("total-findings");
const executiveSummary = document.getElementById("executive-summary");
const severitySummary = document.getElementById("severity-summary");
const gapsTableBody = document.getElementById("gaps-table-body");
const themeToggle = document.querySelector("[data-theme-toggle]");
const root = document.documentElement;

let currentTheme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
root.setAttribute("data-theme", currentTheme);

themeToggle.addEventListener("click", () => {
  currentTheme = currentTheme === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", currentTheme);
});

function badgeClass(risk) {
  const value = (risk || "").toLowerCase();
  if (value === "critical") return "badge badge-critical";
  if (value === "high") return "badge badge-high";
  if (value === "medium") return "badge badge-medium";
  return "badge badge-low";
}

function renderExecutiveSummary(data) {
  executiveSummary.innerHTML = `
    <div class="summary-item"><span class="muted">Target</span><strong>${data.target ?? "--"}</strong></div>
    <div class="summary-item"><span class="muted">Host Status</span><strong>${data.host_status ?? "--"}</strong></div>
    <div class="summary-item"><span class="muted">Posture</span><strong>${data.posture ?? "--"}</strong></div>
    <div class="summary-item"><span class="muted">Total Findings</span><strong>${data.total_findings ?? 0}</strong></div>
  `;
}

function renderSeveritySummary(data) {
  severitySummary.innerHTML = `
    <div class="severity-item"><span class="muted">Critical</span><strong>${data.Critical ?? 0}</strong></div>
    <div class="severity-item"><span class="muted">High</span><strong>${data.High ?? 0}</strong></div>
    <div class="severity-item"><span class="muted">Medium</span><strong>${data.Medium ?? 0}</strong></div>
    <div class="severity-item"><span class="muted">Low</span><strong>${data.Low ?? 0}</strong></div>
  `;
}

function renderGapsTable(gaps) {
  if (!gaps || gaps.length === 0) {
    gapsTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="muted">No compliance gaps were detected in this assessment.</td>
      </tr>
    `;
    return;
  }

  gapsTableBody.innerHTML = gaps.map(item => `
    <tr>
      <td>${item.title ?? "--"}</td>
      <td>${item.service ?? "--"}</td>
      <td><span class="${badgeClass(item.risk_level)}">${item.risk_level ?? "Low"}</span></td>
      <td>${item.nca_control ?? "--"}</td>
      <td>${item.source ?? "--"}</td>
      <td>${item.deduction ?? 0}</td>
      <td>${item.remediation ?? "--"}</td>
    </tr>
  `).join("");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const target = document.getElementById("target").value.trim();
  const scanProfile = document.getElementById("scan_profile").value;

  if (!target) {
    formStatus.textContent = "Please enter a target IP or domain.";
    return;
  }

  formStatus.textContent = "Running assessment...";
  resultsSection.classList.add("hidden");

  try {
    const response = await fetch("/api/start-assessment", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        target: target,
        scan_profile: scanProfile
      })
    });

    const data = await response.json();

    if (!response.ok || data.status === "error") {
      formStatus.textContent = data.message || "Assessment failed.";
      return;
    }

    finalScore.textContent = `${data.score?.final_score ?? "--"}%`;
    totalDeduction.textContent = data.score?.total_deduction ?? "--";
    posture.textContent = data.executive_summary?.posture ?? "--";
    totalFindings.textContent = data.summary?.total_findings ?? 0;

    renderExecutiveSummary(data.executive_summary || {});
    renderSeveritySummary(data.score?.severity_summary || {});
    renderGapsTable(data.compliance_gaps || []);

    resultsSection.classList.remove("hidden");
    formStatus.textContent = "Assessment completed successfully.";
  } catch (error) {
    formStatus.textContent = "Unable to connect to the backend service.";
  }
});