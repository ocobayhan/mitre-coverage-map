import os

from waitress import serve

import app as application


def main():
    secret = os.environ.get("SOC_SECRET_KEY", "").strip()
    if not secret or secret == "change-this-in-production":
        raise RuntimeError("SOC_SECRET_KEY must be set for production serving")

    host = os.environ.get("SOC_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_PORT", "8000"))
    threads = max(4, int(os.environ.get("SOC_THREADS", "8")))
    application.init_db()
    serve(
        application.app,
        host=host,
        port=port,
        threads=threads,
        ident="SOC Coverage Map",
        clear_untrusted_proxy_headers=True,
    )


if __name__ == "__main__":
    main()
