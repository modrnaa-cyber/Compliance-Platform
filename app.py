from flask import Flask, jsonify, render_template
from flask_cors import CORS
from config import Config
from routes.assessment_routes import assessment_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)

    app.register_blueprint(assessment_bp, url_prefix="/api")

    @app.route("/", methods=["GET"])
    def home():
        return render_template("index.html")

    @app.route("/health-ui", methods=["GET"])
    def health_ui():
        return jsonify({
            "status": "ok",
            "service": app.config["APP_NAME"],
            "message": "UI is available"
        })

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )