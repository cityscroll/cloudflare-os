# Access service administrators

Access deployments can grant administrator access to individual service tokens through
`CF_ACCESS_SERVICE_ADMINS`, an array of Cloudflare Access Client IDs (or a JSON-encoded
array). It defaults to no service access. Keep human identities in `ADMINS`.

The backend verifies the Access assertion signature, issuer and audience before reading
`common_name`. A service assertion must have a listed Client ID and no email identity.
Its account is named `cf-access-service:<client-id>` and cannot be admitted through the
human administrator list. An explicitly configured service account can be provisioned
when public signups are closed. Removing its entry denies subsequent authentication.
Existing RPC capabilities retain their normal lifetime; removing a grant does not
retroactively revoke an already issued capability.

Configure an Access Service Auth policy scoped to the intended application and token.
Send the service credentials only in Access headers, with `Origin` equal to the Workshop
origin. Never put the secret in deployment variables or URLs. The ordinary `/api`
Cap’n Web interface then supports `authenticateFromCfAccess()`, `amIAdmin()` and
`getAdminApi()` for that distinct service account.

`GET /api/admin-auth` uses the same verified identity and administrator decision as RPC.
It returns `workshop-admin-auth.v1`, `authenticated: true`, `admin: true`, and
`principal_type`. For a service it also returns its own nonsecret `client_id`; it never
looks up an identity from query parameters. The response is not cached. Missing,
invalid, cross-origin, nonadministrator and unconfigured service callers receive 403.
It has no account-creation or settings side effects and is unavailable outside Access mode.

This fork keeps the service-administrator patch on the deployment’s existing upstream
baseline. Changes are limited to authentication and its behavioral tests; adopting newer
upstream versions remains a separate reviewed dependency update.
