FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Unprivileged user: a compromise of the app doesn't hand over root in the container
RUN useradd --create-home --uid 10001 vaultkeep

WORKDIR /app

# Runtime dependencies only - no test or lint tools in the image
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only the application package; tests, attacks, docs and secrets stay out
COPY vaultkeep/ vaultkeep/

# Vault folder owned by the app user, so a fresh volume inherits the right owner
RUN mkdir -p /home/vaultkeep/.vaultkeep && chown vaultkeep:vaultkeep /home/vaultkeep/.vaultkeep

USER vaultkeep
EXPOSE 5000

# gunicorn instead of Flask's development server. One worker because the rate
# limiter keeps its counters in memory; threads let requests overlap.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "vaultkeep.web.app:create_app()"]
