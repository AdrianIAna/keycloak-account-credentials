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

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class AccountCredentialsResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final int deleteMaxAuthAge;

    public AccountCredentialsResourceProvider(KeycloakSession session, int deleteMaxAuthAge) {
        this.session = session;
        this.deleteMaxAuthAge = deleteMaxAuthAge;
    }

    @Override
    public Object getResource() {
        return new AccountCredentialsResource(session, deleteMaxAuthAge);
    }

    @Override
    public void close() {
        // no-op
    }
}
