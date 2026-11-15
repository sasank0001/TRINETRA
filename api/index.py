import os
import sys

# Ensure root project directory is added to sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app as flask_app


class VercelPathMiddleware:
    """
    WSGI middleware for Vercel Serverless Functions.
    Restores the original requested URL path from Vercel's rewrite headers
    (such as HTTP_X_MATCHED_PATH) so Flask routes correctly instead of seeing /api/index.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched_path = environ.get("HTTP_X_MATCHED_PATH")
        if matched_path:
            environ["PATH_INFO"] = matched_path
        elif environ.get("PATH_INFO", "").startswith("/api/index"):
            sub = environ["PATH_INFO"][len("/api/index"):]
            environ["PATH_INFO"] = sub if sub else "/"

        return self.wsgi_app(environ, start_response)


app = VercelPathMiddleware(flask_app)
