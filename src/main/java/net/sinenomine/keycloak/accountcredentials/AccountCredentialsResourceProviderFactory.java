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
 * <p>No provider-specific configuration: a user's credential inventory is a
 * handful of rows, so there is nothing to cap or tune. The provider can be
 * disabled wholesale via the standard SPI switch
 * ({@code --spi-realm-restapi-extension--account-credentials--enabled=false}).
 */
public class AccountCredentialsResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "account-credentials";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new AccountCredentialsResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration
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
