# Keycloak / OIDC

A Keycloak service is available behind the `oidc` Compose profile:

```bash
docker compose --profile oidc up keycloak
# http://localhost:8081
```

Current state: ATLAS supports native JWT login with MFA and stores OIDC settings
(`ATLAS_OIDC_ENABLED`, `ATLAS_OIDC_ISSUER`, `ATLAS_OIDC_CLIENT_ID`,
`ATLAS_OIDC_JWKS_URL`). **OIDC token validation is not yet wired**; do not enable
`ATLAS_OIDC_ENABLED` expecting external identity federation until that adapter is
completed (tracked in DEVELOPMENT_STATUS.md).

Intended realm shape when implemented:

- realm `atlas`, client `atlas-web` (public PKCE) and `atlas-api` (audience),
- role mapper for the six ATLAS role keys,
- MFA required for privileged roles,
- short access-token lifetime with refresh rotation.
