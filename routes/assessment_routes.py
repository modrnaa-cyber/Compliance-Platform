from flask import Blueprint, jsonify, request
from engine.assessment_engine import build_assessment

assessment_bp = Blueprint("assessment", __name__)


@assessment_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "service": "compliance-platform",
        "message": "Backend is running successfully"
    }), 200


@assessment_bp.route("/start-assessment", methods=["POST"])
def start_assessment():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    scan_profile = data.get("scan_profile", "standard").strip().lower()

    allowed_profiles = ["quick", "standard", "deep"]

    if not target:
        return jsonify({
            "status": "error",
            "message": "Target is required"
        }), 400

    if scan_profile not in allowed_profiles:
        return jsonify({
            "status": "error",
            "message": "Invalid scan profile. Use quick, standard, or deep."
        }), 400

    assessment_result = build_assessment(target, scan_profile)
    return jsonify(assessment_result), 200