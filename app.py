"""NoteItUp - an encrypted notes app that runs on localhost.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from config import Config, ensure_secret_key
from models import close_db, init_db
from security import check_csrf, csrf_token, load_user

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
       "script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = ensure_secret_key()
    Path(app.config["STORAGE_DIR"]).mkdir(parents=True, exist_ok=True)

    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    from routes import auth, notes, settings, tasks
    for module in (auth, notes, tasks, settings):
        app.register_blueprint(module.bp)

    @app.before_request
    def guard():
        load_user()
        check_csrf()

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token}

    @app.after_request
    def harden(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = CSP
        if not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"  # decrypted text must never be cached
        return resp

    @app.errorhandler(HTTPException)
    def http_error(exc):
        if request.path.startswith("/api/"):
            return jsonify(error=exc.description), exc.code
        return f"{exc.code}: {exc.description}", exc.code

    @app.errorhandler(413)
    def too_large(_exc):
        return jsonify(error="That note is too large (2 MB limit)."), 413

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host=application.config["HOST"], port=application.config["PORT"],
                    debug=False)
