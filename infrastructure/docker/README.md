# Docker assets

- Root [`docker-compose.yml`](../../docker-compose.yml) defines the local stack:
  PostgreSQL, Redis, RabbitMQ, API, Celery worker/beat, nginx-served frontend and
  optional observability/Keycloak profiles.
- `backend/Dockerfile` builds the API image and installs `nmap`; other scanner
  binaries belong in a dedicated worker image or sandbox.
- `frontend/Dockerfile` builds the SPA and serves it with nginx.

For production, pin image digests, use a private registry, inject secrets from a
secret manager and run migrations as a separate job.
