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
    Restores the original requested URL path (/scanner, /dashboard, /history, /about)
    from Vercel's proxy/rewrite headers so subroutes and tabs render properly
    instead of collapsing back to the root handler.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        # If Vercel rewrote the path to the internal serverless entrypoint
        if path in ("/api/index", "/api/index.py", "/api", "/api/"):
            # Inspect all headers Vercel may populate with the real incoming route
            for header in (
                "HTTP_X_FORWARDED_URI",
                "HTTP_X_FORWARDED_PATH",
                "HTTP_X_MATCHED_PATH",
                "HTTP_X_VERCEL_FORWARDED_PATH",
                "HTTP_X_REAL_PATH",
            ):
                val = environ.get(header)
                if val and not val.startswith("/api"):
                    # Strip any query parameters from path_info
                    environ["PATH_INFO"] = val.split("?")[0]
                    break
            else:
                environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)


app = VercelPathMiddleware(flask_app)
