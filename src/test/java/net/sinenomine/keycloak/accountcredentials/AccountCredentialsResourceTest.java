/*
 * Copyright 2026 Sine Nomine Associates and contributors
 * Author: Adrian Ana <aana@sinenomine.net>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sinenomine.keycloak.accountcredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import org.keycloak.authentication.requiredactions.util.CredentialDeleteHelper;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.tracing.TracingProvider;

import io.opentelemetry.api.trace.Span;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
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
            try (Stream<CredentialSummary> s = new AccountCredentialsResource(session, 0).getCredentials()) {
                result = s.collect(Collectors.toList());
            }
            assertEquals(2, result.size());
            assertEquals(new CredentialSummary("pk-1", "webauthn-passwordless", "YubiKey", 1723500000000L),
                    result.get(0));
            assertEquals(new CredentialSummary("pw-1", CredentialModel.PASSWORD, null, null), result.get(1));
        }
    }

    // ---- hasManageAccount ------------------------------------------------------

    @Test
    void hasManageAccount_viewProfileOnly_false() {
        assertFalse(AccountCredentialsResource.hasManageAccount(tokenWithAccountRole(AccountRoles.VIEW_PROFILE)));
    }

    @Test
    void hasManageAccount_manageAccount_true() {
        assertTrue(AccountCredentialsResource.hasManageAccount(tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT)));
    }

    // ---- deleteCredential: gates ----------------------------------------------

    @Test
    void deleteCredential_accountClientMissing_notFound() {
        KeycloakSession session = sessionWithAccountClient(null);
        assertThrows(NotFoundException.class,
                () -> new AccountCredentialsResource(session, 0).deleteCredential("x"));
    }

    @Test
    void deleteCredential_noToken_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        try (var ignored = mockAuthenticator(null)) {
            assertThrows(NotAuthorizedException.class,
                    () -> new AccountCredentialsResource(session, 0).deleteCredential("x"));
        }
    }

    @Test
    void deleteCredential_serviceAccount_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("svc", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));
        when(auth.user().getServiceAccountClientLink()).thenReturn("some-client");
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class,
                    () -> new AccountCredentialsResource(session, 0).deleteCredential("x"));
        }
    }

    /** The read role must never authorize a mutation. */
    @Test
    void deleteCredential_viewProfileOnly_forbidden() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(ForbiddenException.class,
                    () -> new AccountCredentialsResource(session, 0).deleteCredential("x"));
        }
    }

    /**
     * An id absent from the caller's own store is 404 — including another
     * user's perfectly real credential id, which is the self-scoping property.
     * Runs the real {@code CredentialDeleteHelper}.
     */
    @Test
    void deleteCredential_unknownId_notFound() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        when(auth.user().credentialManager()).thenReturn(credentialManager);
        // getStoredCredentialById returns null (unstubbed), user is not federated
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotFoundException.class,
                    () -> new AccountCredentialsResource(session, 0).deleteCredential("nope"));
        }
    }

    // ---- deleteCredential: success + events ------------------------------------

    @Test
    void deleteCredential_success_204_firesRemoveCredentialEvent() {
        EventHarness h = eventCapableSession();
        AccessToken token = tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT);
        when(token.getIssuedFor()).thenReturn("portal-client");
        AuthResult auth = authFor("u", token);
        UserModel user = auth.user();

        CredentialModel removed = new CredentialModel();
        removed.setId("pk-1");
        removed.setType("webauthn-passwordless");
        removed.setUserLabel("YubiKey");

        try (var ignored = mockAuthenticator(auth);
                MockedStatic<CredentialDeleteHelper> helper = mockStatic(CredentialDeleteHelper.class)) {
            helper.when(() -> CredentialDeleteHelper.removeCredential(
                    eq(h.session()), eq(user), eq("pk-1"), any())).thenReturn(removed);
            Response response = new AccountCredentialsResource(h.session(), 0).deleteCredential("pk-1");
            assertEquals(204, response.getStatus());
        }

        ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
        verify(h.listener()).onEvent(captor.capture());
        Event fired = captor.getValue();
        assertEquals(EventType.REMOVE_CREDENTIAL, fired.getType());
        assertEquals("u", fired.getUserId());
        assertEquals("portal-client", fired.getClientId());
        assertEquals("203.0.113.7", fired.getIpAddress());
        assertEquals("webauthn-passwordless", fired.getDetails().get(Details.CREDENTIAL_TYPE));
        assertEquals("pk-1", fired.getDetails().get(Details.SELECTED_CREDENTIAL_ID));
        assertEquals("YubiKey", fired.getDetails().get(Details.CREDENTIAL_USER_LABEL));
    }

    /** OTP removal keeps the built-in's legacy REMOVE_TOTP clone. */
    @Test
    void deleteCredential_otp_alsoFiresLegacyRemoveTotp() {
        EventHarness h = eventCapableSession();
        AccessToken token = tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT);
        when(token.getIssuedFor()).thenReturn("portal-client");
        AuthResult auth = authFor("u", token);
        UserModel user = auth.user();

        CredentialModel removed = new CredentialModel();
        removed.setId("otp-1");
        removed.setType(OTPCredentialModel.TYPE);

        try (var ignored = mockAuthenticator(auth);
                MockedStatic<CredentialDeleteHelper> helper = mockStatic(CredentialDeleteHelper.class)) {
            helper.when(() -> CredentialDeleteHelper.removeCredential(
                    eq(h.session()), eq(user), eq("otp-1"), any())).thenReturn(removed);
            assertEquals(204, new AccountCredentialsResource(h.session(), 0).deleteCredential("otp-1").getStatus());
        }

        ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
        verify(h.listener(), times(2)).onEvent(captor.capture());
        assertEquals(EventType.REMOVE_TOTP, captor.getAllValues().get(0).getType());
        assertEquals(EventType.REMOVE_CREDENTIAL, captor.getAllValues().get(1).getType());
    }

    /**
     * The helper contract returns null for legacy federated-credential
     * removals: still 204, but no event — mirroring the built-in. The plain
     * session scaffolding here has none of the event-machinery stubs, so this
     * test passing at all proves the event path never ran.
     */
    @Test
    void deleteCredential_helperReturnsNull_noEvent_still204() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));

        try (var ignored = mockAuthenticator(auth);
                MockedStatic<CredentialDeleteHelper> helper = mockStatic(CredentialDeleteHelper.class)) {
            helper.when(() -> CredentialDeleteHelper.removeCredential(any(), any(), any(), any()))
                    .thenReturn(null);
            assertEquals(204, new AccountCredentialsResource(session, 0).deleteCredential("otp-id").getStatus());
        }
    }

    // ---- deleteCredential: recent-authentication gate --------------------------

    /** A user session whose last interactive authentication is known. */
    private static UserSessionModel sessionAuthedAt(Integer authTimeNote, int started) {
        UserSessionModel us = mock(UserSessionModel.class);
        if (authTimeNote != null) {
            when(us.getNote(AuthenticationManager.AUTH_TIME)).thenReturn(String.valueOf(authTimeNote));
        }
        when(us.getStarted()).thenReturn(started);
        return us;
    }

    /**
     * A stale session is refused with a machine-readable marker: removal is
     * how a takeover consolidates itself, so it must ride a recent, deliberate
     * authentication — the client re-authenticates and retries.
     */
    @Test
    void deleteCredential_staleSession_forbidden_namesReauthentication() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));
        UserSessionModel stale = sessionAuthedAt(Time.currentTime() - 3600, Time.currentTime() - 3600);
        when(auth.session()).thenReturn(stale);
        try (var ignored = mockAuthenticator(auth)) {
            ForbiddenException ex = assertThrows(ForbiddenException.class,
                    () -> new AccountCredentialsResource(session, 60).deleteCredential("pk-1"));
            assertEquals(403, ex.getResponse().getStatus());
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) ex.getResponse().getEntity();
            assertEquals(AccountCredentialsResource.ERROR_REAUTHENTICATION_REQUIRED, body.get("error"));
            assertEquals(60, body.get("maxAuthAgeSeconds"));
        }
    }

    /**
     * The AUTH_TIME note wins over an old session start: a prompt=login pass
     * over an existing SSO session re-freshes exactly that note, which is what
     * lets the client retry with its EXISTING access token.
     */
    @Test
    void deleteCredential_freshNoteOnOldSession_deletes() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));
        UserSessionModel refreshed = sessionAuthedAt(Time.currentTime() - 5, Time.currentTime() - 3600);
        when(auth.session()).thenReturn(refreshed);
        try (var ignored = mockAuthenticator(auth);
                MockedStatic<CredentialDeleteHelper> helper = mockStatic(CredentialDeleteHelper.class)) {
            helper.when(() -> CredentialDeleteHelper.removeCredential(any(), any(), any(), any()))
                    .thenReturn(null);
            assertEquals(204, new AccountCredentialsResource(session, 60).deleteCredential("pk-1").getStatus());
        }
    }

    /** No note, fresh session start — the direct-grant shape — passes. */
    @Test
    void deleteCredential_noNote_freshSessionStart_deletes() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));
        UserSessionModel fresh = sessionAuthedAt(null, Time.currentTime() - 5);
        when(auth.session()).thenReturn(fresh);
        try (var ignored = mockAuthenticator(auth);
                MockedStatic<CredentialDeleteHelper> helper = mockStatic(CredentialDeleteHelper.class)) {
            helper.when(() -> CredentialDeleteHelper.removeCredential(any(), any(), any(), any()))
                    .thenReturn(null);
            assertEquals(204, new AccountCredentialsResource(session, 60).deleteCredential("pk-1").getStatus());
        }
    }

    /** {@code delete-max-auth-age=0} disables the gate wholesale. */
    @Test
    void deleteCredential_gateDisabled_staleSessionStillDeletes() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT));
        UserSessionModel stale = sessionAuthedAt(Time.currentTime() - 3600, Time.currentTime() - 3600);
        when(auth.session()).thenReturn(stale);
        try (var ignored = mockAuthenticator(auth);
                MockedStatic<CredentialDeleteHelper> helper = mockStatic(CredentialDeleteHelper.class)) {
            helper.when(() -> CredentialDeleteHelper.removeCredential(any(), any(), any(), any()))
                    .thenReturn(null);
            assertEquals(204, new AccountCredentialsResource(session, 0).deleteCredential("pk-1").getStatus());
        }
    }

    // ---- authTimeOf ------------------------------------------------------------

    @Test
    void authTimeOf_noteWinsOverStart() {
        UserSessionModel us = sessionAuthedAt(1000, 500);
        assertEquals(1000, AccountCredentialsResource.authTimeOf(us));
    }

    @Test
    void authTimeOf_unparsableNote_fallsBackToStart() {
        UserSessionModel us = mock(UserSessionModel.class);
        when(us.getNote(AuthenticationManager.AUTH_TIME)).thenReturn("not-a-number");
        when(us.getStarted()).thenReturn(500);
        assertEquals(500, AccountCredentialsResource.authTimeOf(us));
    }

    @Test
    void authTimeOf_nullSession_zero() {
        assertEquals(0, AccountCredentialsResource.authTimeOf(null));
    }

    // ---- currentAuthenticatedLevel ---------------------------------------------

    @Test
    void currentAuthenticatedLevel_noAcr_forbidden() {
        RealmModel realm = realmWithClientAcrMap("{\"gold\":2}");
        AccessToken token = tokenIssuedFor("web", null);
        assertThrows(ForbiddenException.class,
                () -> AccountCredentialsResource.currentAuthenticatedLevel(realm, token));
    }

    @Test
    void currentAuthenticatedLevel_mappedAcr_returnsMappedLevel() {
        RealmModel realm = realmWithClientAcrMap("{\"gold\":2}");
        AccessToken token = tokenIssuedFor("web", "gold");
        assertEquals(2, AccountCredentialsResource.currentAuthenticatedLevel(realm, token));
    }

    @Test
    void currentAuthenticatedLevel_numericAcrNotInMap_parsed() {
        RealmModel realm = realmWithClientAcrMap(null);
        AccessToken token = tokenIssuedFor("web", "1");
        assertEquals(1, AccountCredentialsResource.currentAuthenticatedLevel(realm, token));
    }

    @Test
    void currentAuthenticatedLevel_unmappedNonNumericAcr_forbidden() {
        RealmModel realm = realmWithClientAcrMap(null);
        AccessToken token = tokenIssuedFor("web", "bronze");
        assertThrows(ForbiddenException.class,
                () -> AccountCredentialsResource.currentAuthenticatedLevel(realm, token));
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

    /** A session wired for EventBuilder, plus the global listener observing it. */
    private record EventHarness(KeycloakSession session, EventListenerProvider listener) {
    }

    /**
     * Session scaffolding for the event-firing tests: EventBuilder's
     * constructor resolves the realm's listener set and its success() path
     * resolves enabled event types and the tracing provider, so all of those
     * need stubs. Event storage stays off (isEventsEnabled defaults false);
     * the assertion surface is the single global listener.
     */
    private static EventHarness eventCapableSession() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        RealmModel realm = session.getContext().getRealm();
        when(realm.getEventsListenersStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getEnabledEventTypesStream()).thenAnswer(inv -> Stream.empty());

        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        EventListenerProviderFactory listenerFactory = mock(EventListenerProviderFactory.class);
        when(listenerFactory.isGlobal()).thenReturn(true);
        when(listenerFactory.getId()).thenReturn("test-listener");
        when(sessionFactory.getProviderFactoriesStream(EventListenerProvider.class))
                .thenAnswer(inv -> Stream.of(listenerFactory));
        EventListenerProvider listener = mock(EventListenerProvider.class);
        when(session.getProvider(EventListenerProvider.class, "test-listener")).thenReturn(listener);

        TracingProvider tracing = mock(TracingProvider.class);
        when(tracing.getCurrentSpan()).thenReturn(mock(Span.class)); // isRecording() defaults false
        when(session.getProvider(TracingProvider.class)).thenReturn(tracing);

        ClientConnection connection = mock(ClientConnection.class);
        when(connection.getRemoteHost()).thenReturn("203.0.113.7");
        when(session.getContext().getConnection()).thenReturn(connection);

        return new EventHarness(session, listener);
    }

    /**
     * Realm with one client ("web") whose ACR-to-LoA map is the given JSON;
     * null means unconfigured on both the client and its realm.
     */
    private static RealmModel realmWithClientAcrMap(String acrLoaMapJson) {
        RealmModel realm = mock(RealmModel.class);
        ClientModel client = mock(ClientModel.class);
        when(realm.getClientByClientId("web")).thenReturn(client);
        when(client.getAttribute(Constants.ACR_LOA_MAP)).thenReturn(acrLoaMapJson);
        if (acrLoaMapJson == null) {
            when(client.getRealm()).thenReturn(realm); // fallback path reads the realm's map
        }
        return realm;
    }

    private static AccessToken tokenIssuedFor(String clientId, String acr) {
        AccessToken token = mock(AccessToken.class);
        when(token.getIssuedFor()).thenReturn(clientId);
        when(token.getAcr()).thenReturn(acr);
        return token;
    }

    private static void drain(KeycloakSession session) {
        try (Stream<?> s = new AccountCredentialsResource(session, 0).getCredentials()) {
            s.forEach(x -> { });
        }
    }
}
