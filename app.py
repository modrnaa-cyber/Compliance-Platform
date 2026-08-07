from flask import Flask, jsonify, render_template
from flask_cors import CORS
from config import Config
from routes.assessment_routes import assessment_bp
import requests


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)

    @app.route("/", methods=["GET"])
    def home():
        return render_template("index.html")

    @app.route("/health-ui", methods=["GET"])
    def health_ui():
        return jsonify({
            "status": "ok",
            "service": app.config["APP_NAME"],
            "message": "UI is available"
        }), 200

    @app.route("/api/ids-status", methods=["GET"])
    def ids_status_proxy():
        try:
            r = requests.get('http://172.20.10.3:5055/ids-status', timeout=3)
            return jsonify(r.json())
        except:
            return jsonify({
                "connected": False,
                "total_alerts": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "top_signature": "—",
                "alerts": []
            })

    app.register_blueprint(assessment_bp, url_prefix="/api")

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"status": "error", "message": "Internal server error"}), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)