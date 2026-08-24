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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ext.RuntimeDelegate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.utils.KeycloakSessionUtil;

import net.sinenomine.keycloak.accountcredentials.AccountCredentialsResource.CredentialSummary;

class AccountCredentialsResourceTest {

    private static final String ACCOUNT = Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;

    @BeforeAll
    static void pinRuntimeDelegate() {
        // JAX-RS exceptions build a Response in their constructor, which requires a
        // RuntimeDelegate. Two providers sit on the test classpath (resteasy-core for
        // tests, resteasy-reactive-common for @NoCache) — pin resteasy-core's; the
        // reactive one needs server components.
        RuntimeDelegate.setInstance(new org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl());
    }

    @AfterEach
    void clearThreadLocalSession() {
        KeycloakSessionUtil.setKeycloakSession(null);
    }

    // ---- hasAccountAccess ----------------------------------------------------

    @Test
    void hasAccountAccess_nullToken_false() {
        assertFalse(AccountCredentialsResource.hasAccountAccess(null));
    }

    @Test
    void hasAccountAccess_noAccountResourceAccess_false() {
        AccessToken token = mock(AccessToken.class);
        when(token.getResourceAccess(ACCOUNT)).thenReturn(null);
        assertFalse(AccountCredentialsResource.hasAccountAccess(token));
    }

    @Test
    void hasAccountAccess_accountAccessButNoRole_false() {
        // unstubbed isUserInRole(...) defaults to false
        assertFalse(AccountCredentialsResource.hasAccountAccess(tokenWithAccountRole(null)));
    }

    @Test
    void hasAccountAccess_viewProfile_true() {
        assertTrue(AccountCredentialsResource.hasAccountAccess(tokenWithAccountRole(AccountRoles.VIEW_PROFILE)));
    }

    @Test
    void hasAccountAccess_manageAccount_true() {
        assertTrue(AccountCredentialsResource.hasAccountAccess(tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT)));
    }

    // ---- toSummary -----------------------------------------------------------

    @Test
    void toSummary_mapsInventoryFields() {
        CredentialModel model = new CredentialModel();
        model.setId("cred-1");
        model.setType(CredentialModel.PASSWORD);
        model.setUserLabel("My phone");
        model.setCreatedDate(1723500000000L);

        CredentialSummary summary = AccountCredentialsResource.toSummary(model);
        assertEquals("cred-1", summary.id());
        assertEquals(CredentialModel.PASSWORD, summary.type());
        assertEquals("My phone", summary.userLabel());
        assertEquals(1723500000000L, summary.createdDate());
    }

    @Test
    void toSummary_nullLabelAndDate_preserved() {
        CredentialModel model = new CredentialModel();
        model.setId("cred-2");
        model.setType("webauthn-passwordless");

        CredentialSummary summary = AccountCredentialsResource.toSummary(model);
        assertEquals("cred-2", summary.id());
        assertEquals("webauthn-passwordless", summary.type());
        assertNull(summary.userLabel());
        assertNull(summary.createdDate());
    }

    /**
     * The response type must be structurally incapable of carrying secrets:
     * this pins the record's component set, so adding a field that could leak
     * credentialData/secretData is a deliberate, test-visible act.
     */
    @Test
    void credentialSummary_componentSet_isClosed() {
        Set<String> components = Arrays.stream(CredentialSummary.class.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());
        assertEquals(Set.of("id", "type", "userLabel", "createdDate"), components);
    }

    @Test
    void toSummary_secretBearingModel_secretsCannotMap() {
        CredentialModel model = new CredentialModel();
        model.setId("cred-3");
        model.setType(CredentialModel.OTP);
        model.setCredentialData("{\"digits\":6}");
        model.setSecretData("{\"value\":\"SUPER-SECRET\"}");

        CredentialSummary summary = AccountCredentialsResource.toSummary(model);
        // The record has no secret-bearing components (pinned above); the
        // values that exist must not smuggle them either.
        for (RecordComponent c : CredentialSummary.class.getRecordComponents()) {
            try {
                Object value = c.getAccessor().invoke(summary);
                if (value != null) {
                    assertFalse(String.valueOf(value).contains("SUPER-SECRET"),
                            "secret leaked through component " + c.getName());
                }
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        }
    }

    // ---- account client gate -------------------------------------------------

    @Test
    void getCredentials_accountClientMissing_notFound() {
        KeycloakSession session = sessionWithAccountClient(null);
        assertThrows(NotFoundException.class, () -> drain(session));
    }

    @Test
    void getCredentials_accountClientDisabled_notFound() {
        ClientModel disabled = mock(ClientModel.class); // isEnabled() defaults to false
        KeycloakSession session = sessionWithAccountClient(disabled);
        assertThrows(NotFoundException.class, () -> drain(session));
    }

    // ---- getCredentials: gate ordering ----------------------------------------

    @Test
    void getCredentials_noToken_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        try (var ignored = mockAuthenticator(null)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getCredentials_missingUser_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        AuthResult auth = mock(AuthResult.class);
        when(auth.user()).thenReturn(null);
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getCredentials_noIntrospectionProvider_unauthorized() {
        // wire token missing aud/resource_access and no introspection provider
        // available → cannot establish the account audience → 401
        KeycloakSession session = sessionWithEnabledAccountClient();
        AuthResult auth = authFor("u", mock(AccessToken.class));
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getCredentials_recoveredTokenWrongAudience_unauthorized() {
        // introspection recovers a token, but its aud still lacks "account" → 401
        KeycloakSession session = sessionWithEnabledAccountClient();
        AccessToken wireToken = mock(AccessToken.class);
        AccessToken recovered = mock(AccessToken.class); // hasAudience defaults to false
        when(recovered.getAudience()).thenReturn(new String[] {"other-client"});
        UserSessionModel userSession = mock(UserSessionModel.class);
        AccessTokenIntrospectionProvider introspection = mock(AccessTokenIntrospectionProvider.class);
        when(introspection.transformAccessToken(wireToken, userSession)).thenReturn(recovered);
        when(session.getProvider(TokenIntrospectionProvider.class,
                AccessTokenIntrospectionProviderFactory.ACCESS_TOKEN_TYPE)).thenReturn(introspection);
        AuthResult auth = authFor("u", wireToken);
        when(auth.session()).thenReturn(userSession);
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getCredentials_serviceAccount_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("svc", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));
        when(auth.user().getServiceAccountClientLink()).thenReturn("some-client");
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getCredentials_accountAudienceWithoutRole_forbidden() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(null));
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(ForbiddenException.class, () -> drain(session));
        }
    }

    // ---- getCredentials: happy path -------------------------------------------

    @Test
    void getCredentials_returnsOwnInventory_only() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);

        CredentialModel passkey = new CredentialModel();
        passkey.setId("pk-1");
        passkey.setType("webauthn-passwordless");
        passkey.setUserLabel("YubiKey");
        passkey.setCreatedDate(1723500000000L);
        passkey.setSecretData("{\"value\":\"SUPER-SECRET\"}");

        CredentialModel password = new CredentialModel();
        password.setId("pw-1");
        password.setType(CredentialModel.PASSWORD);

        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        when(credentialManager.getStoredCredentialsStream()).thenReturn(Stream.of(passkey, password));
        when(auth.user().credentialManager()).thenReturn(credentialManager);

        try (var ignored = mockAuthenticator(auth)) {
            List<CredentialSummary> result;
            try (Stream<CredentialSummary> s = new AccountCredentialsResource(session).getCredentials()) {
                result = s.collect(Collectors.toList());
            }
            assertEquals(2, result.size());
            assertEquals(new CredentialSummary("pk-1", "webauthn-passwordless", "YubiKey", 1723500000000L),
                    result.get(0));
            assertEquals(new CredentialSummary("pw-1", CredentialModel.PASSWORD, null, null), result.get(1));
        }
    }

    // ---- helpers -------------------------------------------------------------

    /**
     * Token whose {@code aud} contains {@code account}; {@code role} may be null
     * for an account-audience token without account roles.
     */
    private static AccessToken tokenWithAccountRole(String role) {
        AccessToken.Access access = mock(AccessToken.Access.class);
        if (role != null) {
            when(access.isUserInRole(role)).thenReturn(true);
        }
        AccessToken token = mock(AccessToken.class);
        when(token.getResourceAccess(ACCOUNT)).thenReturn(access);
        when(token.getAudience()).thenReturn(new String[] {ACCOUNT});
        when(token.hasAudience(ACCOUNT)).thenReturn(true);
        return token;
    }

    private static AuthResult authFor(String userId, AccessToken token) {
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(userId);
        AuthResult auth = mock(AuthResult.class);
        when(auth.user()).thenReturn(user);
        when(auth.token()).thenReturn(token);
        return auth;
    }

    /** Session whose realm has the given {@code account} client (may be null). */
    private static KeycloakSession sessionWithAccountClient(ClientModel accountClient) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getClientByClientId(ACCOUNT)).thenReturn(accountClient);
        KeycloakContext ctx = mock(KeycloakContext.class);
        when(ctx.getRealm()).thenReturn(realm);
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(ctx);
        return session;
    }

    private static KeycloakSession sessionWithEnabledAccountClient() {
        ClientModel accountClient = mock(ClientModel.class);
        when(accountClient.isEnabled()).thenReturn(true);
        return sessionWithAccountClient(accountClient);
    }

    /** Wire a Cors provider into the session and bind the thread-local. */
    private static Cors corsFor(KeycloakSession session) {
        Cors cors = mock(Cors.class, RETURNS_SELF);
        when(session.getProvider(Cors.class)).thenReturn(cors);
        // Cors.builder() resolves the session from the thread-local
        KeycloakSessionUtil.setKeycloakSession(session);
        return cors;
    }

    private static org.mockito.MockedConstruction<AppAuthManager.BearerTokenAuthenticator> mockAuthenticator(AuthResult result) {
        return mockConstruction(AppAuthManager.BearerTokenAuthenticator.class,
                (mockAuth, ctx) -> when(mockAuth.authenticate()).thenReturn(result));
    }

    private static void drain(KeycloakSession session) {
        try (Stream<?> s = new AccountCredentialsResource(session).getCredentials()) {
            s.forEach(x -> { });
        }
    }
}
