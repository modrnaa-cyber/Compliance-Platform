import threading
import time
import uuid

from flask import Blueprint, jsonify, request
from services.nmap_service import NmapService
from services.openvas_service import OpenVASService
from services.whatweb_service import WhatWebService
from services.testssl_service import TestSSLService
from services.normalization_service import NormalizationService
from services.compliance_service import ComplianceService
from services.ids_service import get_ids_summary

assessment_bp = Blueprint("assessment", __name__)

JOBS = {}


def update_job(job_id, **kwargs):
    if job_id not in JOBS:
        return
    JOBS[job_id].update(kwargs)
    JOBS[job_id]["updated_at"] = time.time()


def get_nmap_mode(service_type):
    mapping = {
        "quick_internal":    "quick_internal",
        "standard_internal": "standard_internal",
        "deep_internal":     "deep_internal",
        "vulners_quick":     "quick_internal",
        "vulners_standard":  "standard_internal",
        "vulners_deep":      "deep_internal",
        "hybrid_quick":      "quick_internal",
        "hybrid_standard":   "standard_internal",
        "hybrid_deep":       "deep_internal",
        "web_technology":    "quick_internal",
        "ssl_tls_scan":      "quick_internal",
        "full_assessment":   "deep_internal",
    }
    return mapping.get(service_type, "standard_internal")


def should_run_nmap(service_type):
    return service_type in [
        "quick_internal", "standard_internal", "deep_internal",
        "vulners_quick", "vulners_standard", "vulners_deep",
        "hybrid_quick", "hybrid_standard", "hybrid_deep",
        "web_technology", "ssl_tls_scan", "full_assessment",
    ]


def should_run_openvas(service_type):
    return service_type in [
        "openvas_basic", "openvas_advanced", "openvas_web",
        "hybrid_quick", "hybrid_standard", "hybrid_deep",
        "full_assessment",
    ]


def should_run_whatweb(service_type):
    return service_type in [
        "web_technology", "openvas_web", "full_assessment",
    ]


def should_run_testssl(service_type):
    return service_type in [
        "ssl_tls_scan", "openvas_web", "full_assessment",
    ]


def run_assessment_job(job_id, target, service_type):
    try:
        start_time = time.time()

        update_job(job_id,
            status="running", progress=5,
            stage="Initializing",
            message=f"Starting assessment for {service_type}"
        )

        nmap_service         = NmapService()
        openvas_service      = OpenVASService()
        whatweb_service      = WhatWebService()
        testssl_service      = TestSSLService()
        normalization_service = NormalizationService()
        compliance_service   = ComplianceService()

        raw_nmap = {
            "target": target,
            "mode": service_type,
            "hosts": [],
            "scan_duration": 0,
            "total_open_ports": 0
        }

        raw_openvas = {
            "nessus_meta": {
                "connected": False,
                "used": False,
                "scan_id": None,
                "scan_name": "OpenVAS",
                "status": "Not used",
                "last_modification_date": None,
                "message": "OpenVAS was not used in this assessment."
            },
            "vulnerabilities": []
        }

        all_findings = []

        # ── Nmap ──────────────────────────────────────────
        if should_run_nmap(service_type):
            update_job(job_id, progress=20, stage="Running Nmap",
                message=f"Nmap scan started for {service_type}")

            raw_nmap = nmap_service.scan_target(
                target, get_nmap_mode(service_type)
            )
            all_findings += normalization_service.from_nmap(raw_nmap)

        # ── OpenVAS ───────────────────────────────────────
        if should_run_openvas(service_type):
            update_job(job_id, progress=45, stage="Running OpenVAS",
                message=f"OpenVAS scan started for {service_type}")

            raw_openvas = openvas_service.launch_and_fetch_scan(
                target=target,
                service_type=service_type,
                progress_callback=lambda payload: update_job(job_id, **payload)
            )
            all_findings += normalization_service.from_openvas(raw_openvas, target)

        # ── WhatWeb ───────────────────────────────────────
        if should_run_whatweb(service_type):
            update_job(job_id, progress=65, stage="Running WhatWeb",
                message="Web technology detection started")

            raw_whatweb = whatweb_service.scan_target(target)
            all_findings += normalization_service.from_whatweb(raw_whatweb, target)

        # ── testssl.sh ────────────────────────────────────
        if should_run_testssl(service_type):
            update_job(job_id, progress=75, stage="Running testssl.sh",
                message="SSL/TLS scan started")

            raw_testssl = testssl_service.scan_target(target)
            all_findings += normalization_service.from_testssl(raw_testssl, target)

        # ── Merge & Dashboard ─────────────────────────────
        update_job(job_id, progress=85, stage="Merging",
            message="Combining findings")

        update_job(job_id, progress=92, stage="Building Dashboard",
            message="Preparing compliance dashboard")

        dashboard = compliance_service.build_dashboard(
            target=target,
            mode=service_type,
            raw_nmap=raw_nmap,
            merged_findings=all_findings,
            nessus_meta=raw_openvas.get("nessus_meta", {})
        )

        dashboard["scan_duration"]    = round(time.time() - start_time, 2)
        dashboard["total_open_ports"] = raw_nmap.get("total_open_ports", 0)

        update_job(job_id,
            status="completed", progress=100,
            stage="Completed",
            message=f"Assessment completed successfully for service_type={service_type}",
            result=dashboard
        )

    except Exception as e:
        update_job(job_id,
            status="failed", progress=100,
            stage="Failed", message=str(e)
        )


# ── Routes ────────────────────────────────────────────────


@assessment_bp.route("/start-assessment", methods=["POST"])
def start_assessment():
    try:
        payload      = request.get_json() or {}
        target       = (payload.get("target") or "").strip()
        service_type = (payload.get("service_type") or "").strip()

        if not target:
            return jsonify({"status": "error",
                "message": "Target Domain / IP is required"}), 400

        if not service_type:
            return jsonify({"status": "error",
                "message": "Assessment service is required"}), 400

        job_id = str(uuid.uuid4())

        JOBS[job_id] = {
            "job_id":       job_id,
            "target":       target,
            "service_type": service_type,
            "status":       "queued",
            "progress":     0,
            "stage":        "Queued",
            "message":      f"Assessment queued for service_type={service_type}",
            "result":       None,
            "updated_at":   time.time()
        }

        threading.Thread(
            target=run_assessment_job,
            args=(job_id, target, service_type),
            daemon=True
        ).start()

        return jsonify({
            "status":                "success",
            "message":               "Assessment job created.",
            "job_id":                job_id,
            "received_service_type": service_type
        }), 202

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@assessment_bp.route("/assessment-status/<job_id>", methods=["GET"])
def assessment_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found."}), 404
    return jsonify({"status": "success", "job": job}), 200


@assessment_bp.route('/api/ids-status', methods=['GET'])
def ids_status():
    return jsonify(get_ids_summary())