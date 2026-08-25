/*
 * Copyright 2026 Adrian Ana and contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package net.sinenomine.keycloak.accountcredentials;

import java.util.Map;
import java.util.stream.Stream;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.resteasy.reactive.NoCache;

import org.keycloak.authentication.requiredactions.util.CredentialDeleteHelper;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/**
 * Account-scoped credential-inventory resource:
 *
 * <ul>
 * <li>{@code GET /realms/{realm}/account-credentials/me} — the authenticated
 * caller's own stored credentials: type, user label, creation date, and id.
 * Never secrets: {@code credentialData} and {@code secretData} are not part of
 * the response type at all.</li>
 * <li>{@code DELETE /realms/{realm}/account-credentials/{credentialId}} —
 * remove one of the caller's own credentials, with the exact semantics of the
 * built-in account API's delete (same validation helper, same event).</li>
 * </ul>
 *
 * <p>Why this exists: the built-in Account REST API's credentials endpoint
 * only reports credential types that an <em>enabled authenticator in an active
 * authentication flow</em> references (via {@code CredentialValidator}). A
 * realm whose flows use custom authenticators — a passkey-first flow, for
 * example — is invisible to it: users demonstrably holding
 * {@code webauthn-passwordless} credentials get an answer that omits the type
 * entirely. This resource reads the caller's credential store directly, so the
 * inventory is truthful regardless of how the realm authenticates. The delete
 * exists for the same reason one step later: a credential the built-in listing
 * cannot name is a credential its delete can never be asked to remove.
 *
 * <p>The request pipeline mirrors Keycloak's built-in account API gatekeeping
 * (see {@code AccountLoader}): bearer-token authentication, lightweight-token
 * claim recovery via introspection, an {@code account} audience check, CORS
 * origin enforcement, service-account rejection, and finally the role
 * requirement — {@code view-profile}/{@code manage-account} to read,
 * {@code manage-account} alone to delete, exactly as the built-in account API
 * divides them. Results and removals are always hard-scoped to the token's own
 * subject: the inventory has no user-id parameter, and the delete resolves the
 * credential id inside the caller's own store, so another user's credential id
 * is simply not found.
 */
public class AccountCredentialsResource {

    /** Machine-readable marker in the 403 body when removal needs a fresh login. */
    public static final String ERROR_REAUTHENTICATION_REQUIRED = "reauthentication_required";

    private final KeycloakSession session;
    private final int deleteMaxAuthAge;

    public AccountCredentialsResource(KeycloakSession session, int deleteMaxAuthAge) {
        this.session = session;
        this.deleteMaxAuthAge = deleteMaxAuthAge;
    }

    /**
     * One stored credential, reduced to what an account UI needs to render an
     * inventory. Deliberately a closed set of fields: the secret-bearing
     * {@code credentialData}/{@code secretData} columns cannot leak through a
     * type that never carries them.
     *
     * @param id          credential id (stable handle, e.g. for the remove flow)
     * @param type        credential type, e.g. {@code password}, {@code otp},
     *                    {@code webauthn}, {@code webauthn-passwordless},
     *                    {@code recovery-authn-codes}
     * @param userLabel   the user-assigned device label, may be {@code null}
     * @param createdDate creation time in epoch millis, may be {@code null}
     */
    public record CredentialSummary(String id, String type, String userLabel, Long createdDate) {
    }

    /** The authenticated caller: auth result plus the resolved (full-claim) token. */
    record Caller(AuthResult auth, AccessToken token) {
    }

    /** CORS preflight for browser callers, mirroring the built-in account API. */
    @OPTIONS
    @Path("me")
    public Response preflight() {
        requireEnabledAccountClient();
        return Cors.builder().auth().allowedMethods("GET", "OPTIONS").preflight().add(Response.ok());
    }

    /** CORS preflight for the credential-removal path. */
    @OPTIONS
    @Path("{credentialId}")
    public Response preflightDelete() {
        requireEnabledAccountClient();
        return Cors.builder().auth().allowedMethods("DELETE", "OPTIONS").preflight().add(Response.ok());
    }

    /** @return the caller's own stored credentials, in store order */
    @GET
    @Path("me")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Stream<CredentialSummary> getCredentials() {
        Caller caller = authenticateCaller("GET", false);

        return caller.auth().user().credentialManager()
                .getStoredCredentialsStream()
                .map(AccountCredentialsResource::toSummary);
    }

    /**
     * Remove one of the caller's own credentials.
     *
     * <p>Removing a credential is how an account takeover consolidates itself,
     * so beyond the role check it requires a <em>recent</em> authentication:
     * the caller's session must have authenticated within the configured
     * {@code delete-max-auth-age} window (default 60s; {@code 0} disables).
     * A stale session gets {@code 403} with
     * {@code {"error":"reauthentication_required"}} — the client's cue to send
     * the user through a fresh login ({@code prompt=login}) and retry. The
     * freshness source is the server-side user session ({@code AUTH_TIME}
     * note, falling back to the session start), not a token claim: access
     * tokens from some grants carry no {@code auth_time}, and a
     * re-authentication updates the session the caller's existing token
     * already maps to, so the retry needs no token refresh.
     *
     * <p>Delegates to the same {@code CredentialDeleteHelper} the built-in
     * account API's delete uses, so the semantics are identical: {@code 404}
     * for an id not present in the caller's own store, {@code 400} for a type
     * whose provider does not allow removal (a password, for instance), and
     * {@code 403} when step-up authentication is configured and the current
     * token's level of authentication is below what removing that credential
     * type requires. On success the same {@code REMOVE_CREDENTIAL} event is
     * fired, so realm event listeners (and anything reading the event store)
     * see extension-initiated removals exactly like built-in ones.
     *
     * @param credentialId id of one of the caller's own credentials
     * @return {@code 204 No Content} on success
     */
    @DELETE
    @Path("{credentialId}")
    @NoCache
    public Response deleteCredential(@PathParam("credentialId") String credentialId) {
        Caller caller = authenticateCaller("DELETE", true);
        requireRecentAuthentication(caller);
        UserModel user = caller.auth().user();

        CredentialModel removed = CredentialDeleteHelper.removeCredential(
                session, user, credentialId,
                () -> currentAuthenticatedLevel(session.getContext().getRealm(), caller.token()));

        if (removed != null) {
            EventBuilder event = new EventBuilder(
                    session.getContext().getRealm(), session, session.getContext().getConnection())
                    .client(caller.token().getIssuedFor())
                    .user(user)
                    .session(caller.auth().session())
                    .event(EventType.REMOVE_CREDENTIAL)
                    .detail(Details.CREDENTIAL_TYPE, removed.getType())
                    .detail(Details.SELECTED_CREDENTIAL_ID, credentialId)
                    .detail(Details.CREDENTIAL_USER_LABEL, removed.getUserLabel());
            if (OTPCredentialModel.TYPE.equals(removed.getType())) {
                event.clone().event(EventType.REMOVE_TOTP).success();
            }
            event.success();
        }

        return Response.noContent().build();
    }

    /**
     * Refuse a stale session for credential removal. Freshness comes from the
     * server-side user session: the {@code AUTH_TIME} note (updated by every
     * interactive authentication, including a {@code prompt=login} pass over
     * an existing SSO session) with the session's start time as the fallback
     * (a freshly-created session — a direct grant, for instance — carries the
     * authentication moment as its start and may have no note yet).
     */
    private void requireRecentAuthentication(Caller caller) {
        if (deleteMaxAuthAge <= 0) {
            return;
        }
        int authTime = authTimeOf(caller.auth().session());
        if (Time.currentTime() - authTime > deleteMaxAuthAge) {
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of(
                            "error", ERROR_REAUTHENTICATION_REQUIRED,
                            "maxAuthAgeSeconds", deleteMaxAuthAge))
                    .type(MediaType.APPLICATION_JSON)
                    .build());
        }
    }

    /** The session's last interactive-authentication time, in epoch seconds. */
    static int authTimeOf(UserSessionModel userSession) {
        String note = userSession == null ? null : userSession.getNote(AuthenticationManager.AUTH_TIME);
        if (note != null) {
            try {
                return Integer.parseInt(note);
            } catch (NumberFormatException ignored) {
                // fall through to the session start
            }
        }
        return userSession == null ? 0 : userSession.getStarted();
    }

    /**
     * The shared gate, in the built-in account API's order: enabled account
     * client, bearer authentication, lightweight-token claim recovery,
     * {@code account} audience, CORS, service-account rejection, role.
     *
     * @param method               the HTTP method for CORS enforcement
     * @param requireManageAccount {@code true} for mutations, which need
     *                             {@code manage-account}; {@code false} for
     *                             reads, where {@code view-profile} suffices
     */
    private Caller authenticateCaller(String method, boolean requireManageAccount) {
        requireEnabledAccountClient();

        AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null || authResult.user() == null) {
            throw new NotAuthorizedException("Bearer realm=\"account\"");
        }

        AccessToken token = resolveToken(authResult);
        if (token == null || !token.hasAudience(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {
            throw new NotAuthorizedException("Invalid audience for client " + Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        }

        Cors.builder().checkAllowedOrigins(token).allowedMethods(method).auth().add();

        if (authResult.user().getServiceAccountClientLink() != null) {
            throw new NotAuthorizedException("Service accounts are not allowed to access this service");
        }

        if (requireManageAccount) {
            if (!hasManageAccount(token)) {
                throw new ForbiddenException("Requires account management (manage-account)");
            }
        } else if (!hasAccountAccess(token)) {
            throw new ForbiddenException("Requires account access (view-profile or manage-account)");
        }

        return new Caller(authResult, token);
    }

    /**
     * The endpoint exists only while the realm's {@code account} client does,
     * mirroring the built-in account API ({@code AccountLoader}): a realm that
     * disabled the account client gets {@code 404}, not served inventory.
     */
    private void requireEnabledAccountClient() {
        ClientModel accountClient = session.getContext().getRealm()
                .getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        if (accountClient == null || !accountClient.isEnabled()) {
            throw new NotFoundException("account management not enabled");
        }
    }

    /**
     * Resolve the effective access token. Lightweight access tokens omit the
     * {@code aud} and {@code resource_access} claims from the wire token; recover
     * them via the introspection transform, exactly as the built-in account API
     * does ({@code AccountLoader}).
     */
    private AccessToken resolveToken(AuthResult authResult) {
        AccessToken token = authResult.token();
        if (token != null
                && (token.getAudience() == null
                        || token.getResourceAccess(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID) == null)) {
            AccessTokenIntrospectionProvider provider = (AccessTokenIntrospectionProvider) session.getProvider(
                    TokenIntrospectionProvider.class, AccessTokenIntrospectionProviderFactory.ACCESS_TOKEN_TYPE);
            if (provider != null) {
                token = provider.transformAccessToken(token, authResult.session());
            }
        }
        return token;
    }

    /**
     * Whether the token carries the {@code account} client's {@code view-profile}
     * or {@code manage-account} role.
     */
    static boolean hasAccountAccess(AccessToken token) {
        if (token == null) {
            return false;
        }
        AccessToken.Access access = token.getResourceAccess(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        return access != null
                && (access.isUserInRole(AccountRoles.VIEW_PROFILE)
                        || access.isUserInRole(AccountRoles.MANAGE_ACCOUNT));
    }

    /** Whether the token carries the {@code account} client's {@code manage-account} role. */
    static boolean hasManageAccount(AccessToken token) {
        if (token == null) {
            return false;
        }
        AccessToken.Access access = token.getResourceAccess(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        return access != null && access.isUserInRole(AccountRoles.MANAGE_ACCOUNT);
    }

    /**
     * The caller's current level of authentication, from the token's {@code acr}
     * claim — the built-in account API's logic, verbatim: map through the
     * issuing client's ACR-to-LoA map, fall back to parsing a numeric acr, and
     * refuse tokens that carry no usable acr at all. Feeds the step-up check in
     * {@code CredentialDeleteHelper}.
     */
    static Integer currentAuthenticatedLevel(RealmModel realm, AccessToken token) {
        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        Map<String, Integer> acrLoaMap = AcrUtils.getAcrLoaMap(client);
        String tokenAcr = token.getAcr();
        if (tokenAcr == null) {
            throw new ForbiddenException("No LoA on the token");
        }
        Integer currentAuthenticatedLevel = acrLoaMap.get(tokenAcr);
        if (currentAuthenticatedLevel != null) {
            return currentAuthenticatedLevel;
        }
        try {
            return Integer.parseInt(tokenAcr);
        } catch (NumberFormatException nfe) {
            throw new ForbiddenException("Unsupported acr on the token");
        }
    }

    /** Reduce a stored credential to its inventory summary. Secrets never map. */
    static CredentialSummary toSummary(CredentialModel model) {
        return new CredentialSummary(
                model.getId(), model.getType(), model.getUserLabel(), model.getCreatedDate());
    }
}
