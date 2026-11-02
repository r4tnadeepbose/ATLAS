# ATLAS production Kubernetes notes

`deployment.yaml` provides a single-file baseline: namespace, configuration,
secrets placeholders, PostgreSQL StatefulSet, Redis, RabbitMQ, API, Celery
worker, Celery beat, frontend and an nginx Ingress.

Before applying:

1. Replace every `CHANGE_ME` value in the Secret and RabbitMQ URL.
2. Build and push images:
   - `docker build -t registry.example.com/atlas/backend:1.0.0 ./backend`
   - `docker build -t registry.example.com/atlas/frontend:1.0.0 ./frontend`
3. Use a managed PostgreSQL/Redis/RabbitMQ service in production and remove the
   in-cluster instances from the manifest.
4. Provide a TLS secret named `atlas-tls` (cert-manager recommended).
5. Run migrations as a Job before rolling the API:
   `alembic upgrade head` using the API image and production DATABASE_URL.
6. Install scanner tooling on worker nodes using a dedicated image or a
   sandboxed execution service. The default worker image only ships nmap.
7. Never deploy with `ATLAS_APP_ENV=demo` or `ATLAS_SEED_DEMO_DATA=true`.

Scaling guidance: API replicas are stateless; scale Celery workers horizontally.
PostgreSQL is the source of truth; Redis is used for cache/rate limiting; RabbitMQ
carries background jobs. Long scans must run in workers, never in API pods.
