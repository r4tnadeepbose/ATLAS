# nginx

The SPA container uses [`frontend/nginx.conf`](../../frontend/nginx.conf). It:

- serves `index.html` for client-side routes,
- proxies `/api/` and `/health` to the backend,
- sets security headers,
- allows 25 MB uploads,
- caches immutable static assets.

The Kubernetes Ingress mirrors these settings (`proxy-body-size`, timeouts).
For an external reverse proxy, reproduce the `/api/` prefix proxy and SPA
fallback, and terminate TLS there.
