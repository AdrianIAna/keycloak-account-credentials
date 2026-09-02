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

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Asserts what actually ends up inside the packaged JAR.
 * <p>
 * Runs at the {@code verify} phase, after {@code package} -- a plain unit test
 * cannot see the artifact because it has not been built yet.
 * <p>
 * Two things are pinned here:
 * <ul>
 *   <li>the SPI registration file. Declaring {@code <resources>} in the POM
 *       overrides Maven's default source directory; getting that wrong drops
 *       META-INF/services and Keycloak then loads a JAR that registers nothing,
 *       with the build still green.</li>
 *   <li>META-INF/LICENSE and META-INF/NOTICE. Apache-2.0 4(d) attribution has to
 *       travel with the artifact, and this project is consumed as a JAR dropped
 *       into a Keycloak {@code providers/} directory -- nobody reads the repo root.</li>
 * </ul>
 */
class PackagedJarIT {

    private static final String SERVICES = "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory";
    private static final String PROVIDER_CLASS = "net/sinenomine/keycloak/accountcredentials/AccountCredentialsResourceProviderFactory.class";

    @Test
    void jarCarriesSpiRegistrationAndAttributionFiles() throws IOException {
        String prop = System.getProperty("packaged.jar");
        assertNotNull(prop, "packaged.jar system property not set by failsafe");
        Path jar = Path.of(prop);
        assertTrue(Files.isRegularFile(jar), "packaged JAR not found: " + jar);

        try (JarFile jf = new JarFile(jar.toFile())) {
            Set<String> names = jf.stream().map(JarEntry::getName)
                    .collect(Collectors.toCollection(TreeSet::new));
            String listing = "\nJAR entries:\n  " + String.join("\n  ", names);

            // control: prove we opened a real provider JAR and not an empty shell
            assertTrue(names.contains(PROVIDER_CLASS),
                    "provider class missing -- is this even the right artifact?" + listing);

            assertTrue(names.contains(SERVICES),
                    "SPI registration missing: the <resources> block dropped "
                    + "src/main/resources; this JAR would load and register nothing." + listing);

            assertTrue(names.contains("META-INF/LICENSE"),
                    "META-INF/LICENSE missing from the JAR." + listing);
            assertTrue(names.contains("META-INF/NOTICE"),
                    "META-INF/NOTICE missing from the JAR." + listing);

            String license = read(jf, "META-INF/LICENSE");
            assertTrue(license.contains("Apache License"),
                    "META-INF/LICENSE is not the Apache licence text");

            String notice = read(jf, "META-INF/NOTICE");
            assertTrue(notice.contains("Sine Nomine Associates"),
                    "NOTICE does not name the copyright holder:\n" + notice);
            assertTrue(notice.contains("Originally written by Adrian Ana"),
                    "NOTICE lost the original-author credit:\n" + notice);
        }
    }

    private static String read(JarFile jf, String entry) throws IOException {
        try (InputStream in = jf.getInputStream(jf.getEntry(entry))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
