FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5001
ENV PYTHONUNBUFFERED=1
# Inside the container the dashboard must listen on 0.0.0.0 to be reachable via
# the published port. Access is still gated by the per-session token, and the
# port should only be published to localhost (see docker-compose.yml).
ENV RA_HOST=0.0.0.0
CMD ["python3", "-m", "RansomwareAudit.web.app"]
