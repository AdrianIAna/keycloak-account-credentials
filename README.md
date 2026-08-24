# Keycloak Account Credentials SPI

A Keycloak SPI extension that lets a user retrieve their own credential
inventory (passkeys, OTP, recovery codes, password — types and labels, never
secrets) from the account console or any first-party application, using the
user's own access token. No admin credentials involved.

![CI](https://github.com/AdrianIAna/keycloak-account-credentials/actions/workflows/ci.yml/badge.svg)
![Keycloak](https://img.shields.io/badge/Keycloak-26.x-blue)
![License](https://img.shields.io/github/license/AdrianIAna/keycloak-account-credentials)

Sibling of
[keycloak-account-events](https://github.com/AdrianIAna/keycloak-account-events):
the same auth model, applied to the credential store instead of the event
store.

## Why

An application that wants to prompt "you have no passkey yet — add one" needs
to know which credentials the signed-in user holds. The usual answer is the
Admin REST API, which means handing the application a realm-wide
credential-read capability. That doesn't work for self-service screens, where
an application should answer the question with the user's own token and
nothing more.

In many deployments the Admin API is not even an option: security-conscious
setups firewall it to an internal network, or run their public-facing node
from an image built with `--features-disabled=admin,admin-api`, where admin
endpoints don't exist at all. This extension works in every one of those
setups, because it is entirely user-based — a realm resource authorized by
the caller's own account token, with no admin surface anywhere in the path.

Keycloak's built-in Account REST API has a credentials endpoint, but it only
lists credential types referenced by an *enabled authenticator in an active
authentication flow* (via `CredentialValidator`). A realm using custom
authenticators — a passkey-first flow, for example — can have users
demonstrably holding `webauthn-passwordless` credentials that the built-in
endpoint omits entirely, holders included. This extension reads the caller's
credential store directly, so the inventory is truthful regardless of how the
realm's flows authenticate.

## How It Works

The extension registers a `RealmResourceProvider` that serves:

```
GET /realms/{realm}/account-credentials/me
```

Each request goes through the same gatekeeping as Keycloak's built-in account
API:

1. The `Authorization: Bearer` token is validated (signature, issuer, expiry);
   missing or invalid tokens get a `401`.
2. Lightweight access tokens (which omit `aud`/`resource_access` from the wire
   token) have their claims recovered through Keycloak's introspection
   transform, the same mechanism the built-in account API uses.
3. The token must target the `account` client, else `401`.
4. CORS origins are enforced against the client's configured Web Origins for
   browser callers; a preflight `OPTIONS` handler is included.
5. Service-account tokens (`client_credentials`) are rejected with `401`.
6. The token must carry the `account` client's `view-profile` or
   `manage-account` role, else `403`.
7. The caller's credential store is read, hard-scoped to the token's own
   subject.

There is no user-id request parameter anywhere — nor any request parameter at
all: results are bound to the authenticated subject, so a caller can only ever
read their own credentials.

### Responses

| Status | Meaning |
|--------|---------|
| `200`  | Array of the caller's own stored credentials |
| `401`  | Missing/invalid bearer token, wrong audience, or a service-account token |
| `403`  | Token lacks the account `view-profile`/`manage-account` role, or disallowed CORS origin |
| `404`  | The realm's `account` client is missing or disabled (mirrors the built-in account API) |

A `200` body:

```json
[
  {
    "id": "8f1c2a34-5e77-4a30-9c6c-2f6f1f0f4a11",
    "type": "webauthn-passwordless",
    "userLabel": "YubiKey 5",
    "createdDate": 1723500000000
  },
  {
    "id": "b2d1c9e0-1234-4a5b-8c7d-9e0f1a2b3c4d",
    "type": "password",
    "userLabel": null,
    "createdDate": 1719000000000
  }
]
```

`type` is Keycloak's stored credential type: `password`, `otp`, `webauthn`,
`webauthn-passwordless`, `recovery-authn-codes`, ... A user with no local
credentials (e.g. a purely identity-brokered account) gets `[]`.

Never in a response: `credentialData` and `secretData`. The response type has
no such fields, and a test pins its component set so one cannot be added
silently.

## Compatibility

| Extension | Keycloak |
|-----------|----------|
| 0.1.x     | 26.6 – 26.7 (built against 26.7.2) |

Uses only `RealmResourceProvider`, `SubjectCredentialManager`, and the same
gatekeeping utilities the built-in account API uses.

## Installation

1. Copy the release JAR into Keycloak's providers directory:

   ```bash
   cp keycloak-account-credentials-*.jar /opt/keycloak/providers/
   ```

2. Rebuild the server:

   ```bash
   bin/kc.sh build
   ```

### Configuration

None. The provider can be disabled wholesale:

```
--spi-realm-restapi-extension--account-credentials--enabled=false
```

## Building from Source

```bash
mvn clean verify
```

The JAR lands in `target/keycloak-account-credentials-<version>.jar`.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.
For security problems, follow the [security policy](SECURITY.md) instead of opening
a public issue.

## License

[Apache License 2.0](LICENSE)
