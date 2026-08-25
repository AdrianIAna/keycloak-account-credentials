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

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the account-credentials realm resource. Registers the provider
 * under the realm-relative path segment returned by {@link #getId()}, so the
 * endpoint is served at {@code /realms/{realm}/account-credentials}.
 *
 * <p>One configuration option, {@code delete-max-auth-age}: the maximum age,
 * in seconds, of the caller's authentication for the credential-removal
 * endpoint (default {@value #DEFAULT_DELETE_MAX_AUTH_AGE}; {@code 0} disables
 * the check). Set via the standard SPI option syntax, e.g.
 * {@code --spi-realm-restapi-extension--account-credentials--delete-max-auth-age=300}.
 * The provider can be disabled wholesale via
 * {@code --spi-realm-restapi-extension--account-credentials--enabled=false}.
 */
public class AccountCredentialsResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "account-credentials";

    /**
     * Default freshness window for credential removal, in seconds. Sixty
     * seconds is deliberately "the tap you just did": long enough to cover a
     * reauthenticate-and-retry round trip, short enough that removal always
     * rides a deliberate, recent authentication rather than an old session.
     */
    public static final int DEFAULT_DELETE_MAX_AUTH_AGE = 60;

    private int deleteMaxAuthAge = DEFAULT_DELETE_MAX_AUTH_AGE;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new AccountCredentialsResourceProvider(session, deleteMaxAuthAge);
    }

    @Override
    public void init(Config.Scope config) {
        deleteMaxAuthAge = config.getInt("delete-max-auth-age", DEFAULT_DELETE_MAX_AUTH_AGE);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return ID;
    }
}
