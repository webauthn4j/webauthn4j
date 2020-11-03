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
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ServerPropertyTest {
    private final String rpId = "rp-origin.com";
    private final Origin webApp1Origin = new Origin("https://app1.rp-origin.com");
    private final Origin webApp2Origin = new Origin("https://app2.rp-origin.com");
    private final Origin apk1Origin = new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS-0H1xKCQcfIoGLck");
    private final Origin apk2Origin = new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=");


    @Test
    void constructor_rpId_null() {

        //When
        assertThrows(IllegalArgumentException.class,
                () -> new ServerProperty(webApp1Origin, null, null, null)
        );
    }

    @Test
    void equals_hashCode_test() {
        Challenge challenge = new DefaultChallenge();
        ServerProperty serverPropertyA = TestDataUtil.createServerProperty(challenge);
        ServerProperty serverPropertyB = TestDataUtil.createServerProperty(challenge);

        assertAll(
                () -> assertThat(serverPropertyA).isEqualTo(serverPropertyB),
                () -> assertThat(serverPropertyA).hasSameHashCodeAs(serverPropertyB)
        );
    }

    @Test
    void equals_hashCode_multiple_origin_test() {
        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverPropertyA =
            new ServerProperty(Arrays.asList(webApp1Origin,webApp2Origin,apk1Origin,apk2Origin), rpId, challenge, new byte[32]);
        final ServerProperty serverPropertyB =
            new ServerProperty(Arrays.asList(webApp1Origin,apk1Origin,webApp2Origin,apk2Origin), rpId, challenge, new byte[32]);

        assertAll(
                () -> assertThat(serverPropertyA).isEqualTo(serverPropertyB),
                () -> assertThat(serverPropertyA).hasSameHashCodeAs(serverPropertyB)
        );
    }

    @Deprecated
    @Test
    void test_getters_null_origin_input() {
        final byte[] tokenBindingBytes = "random-token-binding1".getBytes(StandardCharsets.UTF_8);
        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(Collections.emptySet(), rpId, challenge, tokenBindingBytes);
        assertAll(
                ()->assertThat(serverProperty.getOrigins()).isEmpty(),
                ()->assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                ()->assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                ()->assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );
    }

    @Deprecated
    @Test
    void test_getters_null_origins_input() {
        final byte[] tokenBindingBytes = "random-token-binding1".getBytes(StandardCharsets.UTF_8);
        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(Collections.emptySet(), rpId, challenge, tokenBindingBytes);
        assertAll(
                ()->assertThat(serverProperty.getOrigins()).isEmpty(),
                ()->assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                ()->assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                ()->assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );
    }

    @Deprecated
    @Test
    void test_getters_empty_origins_input() {
        final byte[] tokenBindingBytes = "random-token-binding1".getBytes(StandardCharsets.UTF_8);
        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(new ArrayList<>(), rpId, challenge, tokenBindingBytes);
        assertAll(
                ()->assertThat(serverProperty.getOrigins()).isEmpty(),
                ()->assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                ()->assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                ()->assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );
    }

    @Deprecated
    @Test
    void test_getters_with_single_origin_input() {
        final byte[] tokenBindingBytes = "random-token-binding2".getBytes(StandardCharsets.UTF_8);

        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(webApp1Origin, rpId, challenge, tokenBindingBytes);
        assertAll(
                ()->assertThat(serverProperty.getOrigins()).isEqualTo(Collections.singleton(webApp1Origin)),
                ()->assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                ()->assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                ()->assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );

    }


    @Deprecated
    @Test
    void test_getters_with_multiple_origin_input() {
        final byte[] tokenBindingBytes = "random-token-binding3".getBytes(StandardCharsets.UTF_8);

        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(
                        Arrays.asList(webApp1Origin, webApp2Origin, apk1Origin, apk2Origin),
                        rpId, challenge, tokenBindingBytes);


        assertAll(
                () -> assertThat(serverProperty.getOrigins()).containsExactlyInAnyOrder(
                        webApp1Origin, apk1Origin, webApp2Origin, apk2Origin),
                () -> assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                () -> assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                () -> assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );

    }

    @Deprecated
    @Test
    void test_getters_with_repeated_origins_input() {
        final byte[] tokenBindingBytes = "random-token-binding3".getBytes(StandardCharsets.UTF_8);

        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(
                        Arrays.asList(webApp1Origin, webApp1Origin, webApp1Origin, webApp1Origin),
                        rpId, challenge, tokenBindingBytes);


        assertAll(
                () -> assertThat(serverProperty.getOrigins()).containsExactlyInAnyOrder(webApp1Origin),
                () -> assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                () -> assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                () -> assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );
    }

    @Deprecated
    @Test
    void test_getters_with_with_some_duplicated_origins_input() {
        final byte[] tokenBindingBytes = "random-token-binding3".getBytes(StandardCharsets.UTF_8);

        final Challenge challenge = new DefaultChallenge();
        final ServerProperty serverProperty =
                new ServerProperty(
                        Arrays.asList(webApp1Origin, webApp1Origin, apk1Origin, apk1Origin),
                        rpId, challenge, tokenBindingBytes);


        assertAll(
                () -> assertThat(serverProperty.getOrigins()).containsExactlyInAnyOrder(
                        webApp1Origin, apk1Origin),
                () -> assertThat(serverProperty.getRpId()).isEqualTo(rpId),
                () -> assertThat(serverProperty.getChallenge()).isEqualTo(challenge),
                () -> assertThat(serverProperty.getTokenBindingId()).isEqualTo(tokenBindingBytes)
        );

    }
}
