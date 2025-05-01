/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class ServerPropertyTest {
    // Constants
    private static final String RP_ID = "rp-origin.com";
    private static final byte[] TOKEN_BINDING_ID_1 = "random-token-binding1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TOKEN_BINDING_ID_2 = "random-token-binding2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TOKEN_BINDING_ID_3 = "random-token-binding3".getBytes(StandardCharsets.UTF_8);
    
    // Test data
    private final Origin webApp1Origin = new Origin("https://app1.rp-origin.com");
    private final Origin webApp2Origin = new Origin("https://app2.rp-origin.com");
    private final Origin apk1Origin = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
    private final Origin apk2Origin = new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");

    // Shared objects
    private Challenge challenge;
    private HashSet<Origin> multipleOrigins;

    @BeforeEach
    void setUp() {
        challenge = new DefaultChallenge();
        multipleOrigins = new HashSet<>(Arrays.asList(webApp1Origin, webApp2Origin, apk1Origin, apk2Origin));
    }

    @Test
    void nullRpIdShouldThrowException() {
        // Given
        Origin origin = webApp1Origin;
        
        // When/Then
        assertThrows(IllegalArgumentException.class,
                () -> new ServerProperty(origin, null, null)
        );
    }

    @Test
    void constructorWithoutTokenBindingIdShouldSucceed() {
        // Given
        HashSet<Origin> origins = multipleOrigins;
        Origin singleOrigin = webApp1Origin;
        
        // When/Then
        assertThatCode(() -> new ServerProperty(origins, RP_ID, challenge)).doesNotThrowAnyException();
        assertThatCode(() -> new ServerProperty(singleOrigin, RP_ID, challenge)).doesNotThrowAnyException();
    }

    @Test
    void sameValuesShouldBeEqual() {
        // Given
        ServerProperty serverPropertyA = TestDataUtil.createServerProperty(challenge);
        ServerProperty serverPropertyB = TestDataUtil.createServerProperty(challenge);

        // When
        boolean equals = serverPropertyA.equals(serverPropertyB);
        int hashCodeA = serverPropertyA.hashCode();
        int hashCodeB = serverPropertyB.hashCode();

        // Then
        assertAll(
                () -> assertThat(equals).isTrue(),
                () -> assertThat(hashCodeA).isEqualTo(hashCodeB)
        );
    }

    @Test
    void multipleOriginsInDifferentOrderShouldBeEqual() {
        // Given
        final ServerProperty serverPropertyA =
                new ServerProperty(new HashSet<>(Arrays.asList(webApp1Origin, webApp2Origin, apk1Origin, apk2Origin)), RP_ID, challenge);
        final ServerProperty serverPropertyB =
                new ServerProperty(new HashSet<>(Arrays.asList(webApp1Origin, apk1Origin, webApp2Origin, apk2Origin)), RP_ID, challenge);

        // When
        boolean equals = serverPropertyA.equals(serverPropertyB);
        int hashCodeA = serverPropertyA.hashCode();
        int hashCodeB = serverPropertyB.hashCode();

        // Then
        assertAll(
                () -> assertThat(equals).isTrue(),
                () -> assertThat(hashCodeA).isEqualTo(hashCodeB)
        );
    }

    @Test
    void emptyOriginsShouldReturnEmptySet() {
        // Given
        final ServerProperty serverProperty =
                new ServerProperty(Collections.emptySet(), RP_ID, challenge);
        
        // When
        Set<Origin> origins = serverProperty.getOrigins();
        String rpId = serverProperty.getRpId();
        Challenge retrievedChallenge = serverProperty.getChallenge();
        
        // Then
        assertAll(
                () -> assertThat(origins).isEmpty(),
                () -> assertThat(rpId).isEqualTo(RP_ID),
                () -> assertThat(retrievedChallenge).isEqualTo(challenge)
        );
    }

    @Test
    void singleOriginShouldReturnSingletonSet() {
        // Given
        final ServerProperty serverProperty =
                new ServerProperty(webApp1Origin, RP_ID, challenge);
        
        // When
        Set<Origin> origins = serverProperty.getOrigins();
        String rpId = serverProperty.getRpId();
        Challenge retrievedChallenge = serverProperty.getChallenge();
        
        // Then
        assertAll(
                () -> assertThat(origins).isEqualTo(Collections.singleton(webApp1Origin)),
                () -> assertThat(rpId).isEqualTo(RP_ID),
                () -> assertThat(retrievedChallenge).isEqualTo(challenge)
        );
    }

    @Test
    void multipleOriginsShouldReturnAllOrigins() {
        // Given
        final ServerProperty serverProperty =
                new ServerProperty(multipleOrigins, RP_ID, challenge);

        // When
        Set<Origin> origins = serverProperty.getOrigins();
        String rpId = serverProperty.getRpId();
        Challenge retrievedChallenge = serverProperty.getChallenge();
        
        // Then
        assertAll(
                () -> assertThat(origins).containsExactlyInAnyOrder(
                        webApp1Origin, apk1Origin, webApp2Origin, apk2Origin),
                () -> assertThat(rpId).isEqualTo(RP_ID),
                () -> assertThat(retrievedChallenge).isEqualTo(challenge)
        );
    }

    @Test
    void repeatedOriginsShouldReturnUniqueOrigins() {
        // Given
        final ServerProperty serverProperty =
                new ServerProperty(
                        new HashSet<>(Arrays.asList(webApp1Origin, webApp1Origin, webApp1Origin, webApp1Origin)),
                        RP_ID, challenge);

        // When
        Set<Origin> origins = serverProperty.getOrigins();
        String rpId = serverProperty.getRpId();
        Challenge retrievedChallenge = serverProperty.getChallenge();
        
        // Then
        assertAll(
                () -> assertThat(origins).containsExactlyInAnyOrder(webApp1Origin),
                () -> assertThat(rpId).isEqualTo(RP_ID),
                () -> assertThat(retrievedChallenge).isEqualTo(challenge)
        );
    }

    @Test
    void multipleDuplicatedOriginsShouldReturnUniqueOrigins() {
        // Given
        final ServerProperty serverProperty =
                new ServerProperty(
                        new HashSet<>(Arrays.asList(webApp1Origin, webApp1Origin, apk1Origin, apk1Origin)),
                        RP_ID, challenge);

        // When
        Set<Origin> origins = serverProperty.getOrigins();
        String rpId = serverProperty.getRpId();
        Challenge retrievedChallenge = serverProperty.getChallenge();
        
        // Then
        assertAll(
                () -> assertThat(origins).containsExactlyInAnyOrder(
                        webApp1Origin, apk1Origin),
                () -> assertThat(rpId).isEqualTo(RP_ID),
                () -> assertThat(retrievedChallenge).isEqualTo(challenge)
        );
    }

    /**
     * Tests for deprecated token binding API methods
     * These tests are grouped together to make it easier to maintain and eventually
     * remove when the deprecated methods are finally removed from the codebase.
     */
    @Nested
    class DeprecatedTokenBindingApiTests {

        @Deprecated
        @Test
        void withTokenBindingIdShouldBeEqual() {
            // Given
            final ServerProperty serverPropertyA =
                    new ServerProperty(new HashSet<>(Arrays.asList(webApp1Origin, webApp2Origin, apk1Origin, apk2Origin)), RP_ID, challenge, new byte[32]);
            final ServerProperty serverPropertyB =
                    new ServerProperty(new HashSet<>(Arrays.asList(webApp1Origin, apk1Origin, webApp2Origin, apk2Origin)), RP_ID, challenge, new byte[32]);

            // When
            boolean equals = serverPropertyA.equals(serverPropertyB);
            int hashCodeA = serverPropertyA.hashCode();
            int hashCodeB = serverPropertyB.hashCode();

            // Then
            assertAll(
                    () -> assertThat(equals).isTrue(),
                    () -> assertThat(hashCodeA).isEqualTo(hashCodeB)
            );
        }
        
        @Deprecated
        @Test
        void emptyOriginsWithTokenBinding() {
            // Given
            final ServerProperty serverProperty =
                    new ServerProperty(Collections.emptySet(), RP_ID, challenge, TOKEN_BINDING_ID_1);
            
            // When
            Set<Origin> origins = serverProperty.getOrigins();
            String rpId = serverProperty.getRpId();
            Challenge retrievedChallenge = serverProperty.getChallenge();
            byte[] tokenBindingId = serverProperty.getTokenBindingId();
            
            // Then
            assertAll(
                    () -> assertThat(origins).isEmpty(),
                    () -> assertThat(rpId).isEqualTo(RP_ID),
                    () -> assertThat(retrievedChallenge).isEqualTo(challenge),
                    () -> assertThat(tokenBindingId).isEqualTo(TOKEN_BINDING_ID_1)
            );
        }

        @Deprecated
        @Test
        void singleOriginWithTokenBinding() {
            // Given
            final ServerProperty serverProperty =
                    new ServerProperty(webApp1Origin, RP_ID, challenge, TOKEN_BINDING_ID_2);
            
            // When
            Set<Origin> origins = serverProperty.getOrigins();
            String rpId = serverProperty.getRpId();
            Challenge retrievedChallenge = serverProperty.getChallenge();
            byte[] tokenBindingId = serverProperty.getTokenBindingId();
            
            // Then
            assertAll(
                    () -> assertThat(origins).isEqualTo(Collections.singleton(webApp1Origin)),
                    () -> assertThat(rpId).isEqualTo(RP_ID),
                    () -> assertThat(retrievedChallenge).isEqualTo(challenge),
                    () -> assertThat(tokenBindingId).isEqualTo(TOKEN_BINDING_ID_2)
            );
        }

        @Deprecated
        @Test
        void multipleOriginsWithTokenBinding() {
            // Given
            final ServerProperty serverProperty =
                    new ServerProperty(multipleOrigins, RP_ID, challenge, TOKEN_BINDING_ID_3);

            // When
            Set<Origin> origins = serverProperty.getOrigins();
            String rpId = serverProperty.getRpId();
            Challenge retrievedChallenge = serverProperty.getChallenge();
            byte[] tokenBindingId = serverProperty.getTokenBindingId();
            
            // Then
            assertAll(
                    () -> assertThat(origins).containsExactlyInAnyOrder(
                            webApp1Origin, apk1Origin, webApp2Origin, apk2Origin),
                    () -> assertThat(rpId).isEqualTo(RP_ID),
                    () -> assertThat(retrievedChallenge).isEqualTo(challenge),
                    () -> assertThat(tokenBindingId).isEqualTo(TOKEN_BINDING_ID_3)
            );
        }

        @Deprecated
        @Test
        void repeatedOriginsWithTokenBinding() {
            // Given
            final ServerProperty serverProperty =
                    new ServerProperty(
                            new HashSet<>(Arrays.asList(webApp1Origin, webApp1Origin, webApp1Origin, webApp1Origin)),
                            RP_ID, challenge, TOKEN_BINDING_ID_3);

            // When
            Set<Origin> origins = serverProperty.getOrigins();
            String rpId = serverProperty.getRpId();
            Challenge retrievedChallenge = serverProperty.getChallenge();
            byte[] tokenBindingId = serverProperty.getTokenBindingId();
            
            // Then
            assertAll(
                    () -> assertThat(origins).containsExactlyInAnyOrder(webApp1Origin),
                    () -> assertThat(rpId).isEqualTo(RP_ID),
                    () -> assertThat(retrievedChallenge).isEqualTo(challenge),
                    () -> assertThat(tokenBindingId).isEqualTo(TOKEN_BINDING_ID_3)
            );
        }

        @Deprecated
        @Test
        void multipleDuplicatedOriginsWithTokenBinding() {
            // Given
            final ServerProperty serverProperty =
                    new ServerProperty(
                            new HashSet<>(Arrays.asList(webApp1Origin, webApp1Origin, apk1Origin, apk1Origin)),
                            RP_ID, challenge, TOKEN_BINDING_ID_3);

            // When
            Set<Origin> origins = serverProperty.getOrigins();
            String rpId = serverProperty.getRpId();
            Challenge retrievedChallenge = serverProperty.getChallenge();
            byte[] tokenBindingId = serverProperty.getTokenBindingId();
            
            // Then
            assertAll(
                    () -> assertThat(origins).containsExactlyInAnyOrder(
                            webApp1Origin, apk1Origin),
                    () -> assertThat(rpId).isEqualTo(RP_ID),
                    () -> assertThat(retrievedChallenge).isEqualTo(challenge),
                    () -> assertThat(tokenBindingId).isEqualTo(TOKEN_BINDING_ID_3)
            );
        }
    }
}
