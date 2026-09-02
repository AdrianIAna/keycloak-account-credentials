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
