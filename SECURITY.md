# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |

Each release is built and tested against the Keycloak versions listed in the
README compatibility table.

## Reporting a Vulnerability

Please don't open a public issue for security problems. Report privately via
[GitHub Security Advisories](../../security/advisories/new) ("Report a
vulnerability" on the repository's Security tab).

You can expect an acknowledgement within a few days. Once a fix is available,
the advisory gets published together with a patched release.

## How access control works

- The endpoint serves only the authenticated caller's own credentials: the read
  is bound to the validated token's subject, and there is no user-id request
  parameter (nor any request parameter at all).
- Requests pass the same gatekeeping as Keycloak's built-in account API:
  bearer-token validation, `account` audience check, CORS origin enforcement,
  service-account rejection, and the `view-profile`/`manage-account` role
  requirement.
- Secrets never leave the store: the response type has no `credentialData` or
  `secretData` fields, and a test pins its component set so one cannot be
  added silently.
