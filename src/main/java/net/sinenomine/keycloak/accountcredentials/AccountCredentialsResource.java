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

import java.util.stream.Stream;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.resteasy.reactive.NoCache;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/**
 * Account-scoped credential-inventory resource serving
 * {@code GET /realms/{realm}/account-credentials/me}: the authenticated
 * caller's own stored credentials — type, user label, creation date, and id.
 * Never secrets: {@code credentialData} and {@code secretData} are not part of
 * the response type at all.
 *
 * <p>Why this exists: the built-in Account REST API's credentials endpoint
 * only reports credential types that an <em>enabled authenticator in an active
 * authentication flow</em> references (via {@code CredentialValidator}). A
 * realm whose flows use custom authenticators — a passkey-first flow, for
 * example — is invisible to it: users demonstrably holding
 * {@code webauthn-passwordless} credentials get an answer that omits the type
 * entirely. This resource reads the caller's credential store directly, so the
 * inventory is truthful regardless of how the realm authenticates.
 *
 * <p>The request pipeline mirrors Keycloak's built-in account API gatekeeping
 * (see {@code AccountLoader}): bearer-token authentication, lightweight-token
 * claim recovery via introspection, an {@code account} audience check, CORS
 * origin enforcement, service-account rejection, and finally the
 * {@code view-profile}/{@code manage-account} role requirement. Results are
 * always hard-scoped to the token's own subject — there is no user-id request
 * parameter (nor any parameter at all), so a caller can never read another
 * user's credentials.
 */
public class AccountCredentialsResource {

    private final KeycloakSession session;

    public AccountCredentialsResource(KeycloakSession session) {
        this.session = session;
    }

    /**
     * One stored credential, reduced to what an account UI needs to render an
     * inventory. Deliberately a closed set of fields: the secret-bearing
     * {@code credentialData}/{@code secretData} columns cannot leak through a
     * type that never carries them.
     *
     * @param id          credential id (stable handle, e.g. for a future remove flow)
     * @param type        credential type, e.g. {@code password}, {@code otp},
     *                    {@code webauthn}, {@code webauthn-passwordless},
     *                    {@code recovery-authn-codes}
     * @param userLabel   the user-assigned device label, may be {@code null}
     * @param createdDate creation time in epoch millis, may be {@code null}
     */
    public record CredentialSummary(String id, String type, String userLabel, Long createdDate) {
    }

    /** CORS preflight for browser callers, mirroring the built-in account API. */
    @OPTIONS
    @Path("me")
    public Response preflight() {
        requireEnabledAccountClient();
        return Cors.builder().auth().allowedMethods("GET", "OPTIONS").preflight().add(Response.ok());
    }

    /** @return the caller's own stored credentials, in store order */
    @GET
    @Path("me")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Stream<CredentialSummary> getCredentials() {
        requireEnabledAccountClient();

        AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null || authResult.user() == null) {
            throw new NotAuthorizedException("Bearer realm=\"account\"");
        }

        AccessToken token = resolveToken(authResult);
        if (token == null || !token.hasAudience(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {
            throw new NotAuthorizedException("Invalid audience for client " + Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        }

        Cors.builder().checkAllowedOrigins(token).allowedMethods("GET").auth().add();

        if (authResult.user().getServiceAccountClientLink() != null) {
            throw new NotAuthorizedException("Service accounts are not allowed to access this service");
        }

        if (!hasAccountAccess(token)) {
            throw new ForbiddenException("Requires account access (view-profile or manage-account)");
        }

        return authResult.user().credentialManager()
                .getStoredCredentialsStream()
                .map(AccountCredentialsResource::toSummary);
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

    /** Reduce a stored credential to its inventory summary. Secrets never map. */
    static CredentialSummary toSummary(CredentialModel model) {
        return new CredentialSummary(
                model.getId(), model.getType(), model.getUserLabel(), model.getCreatedDate());
    }
}
