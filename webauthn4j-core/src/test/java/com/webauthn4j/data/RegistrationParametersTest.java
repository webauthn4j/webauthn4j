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

package com.webauthn4j.data;


import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@SuppressWarnings("ConstantConditions")
class RegistrationParametersTest {

    @Test
    void constructor_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        RegistrationParameters instance =
                new RegistrationParameters(
                        serverProperty,
                        null,
                        false,
                        true
                );

        assertThat(instance.getServerProperty()).isEqualTo(serverProperty);
        assertThat(instance.getPubKeyCredParams()).isNull();
        assertThat(instance.isUserVerificationRequired()).isFalse();
        assertThat(instance.isUserPresenceRequired()).isTrue();
    }

    @Deprecated
    @Test
    void constructor_without_pubKeyCredParams_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        RegistrationParameters instance =
                new RegistrationParameters(
                        serverProperty,
                        false,
                        true
                );

        assertThat(instance.getServerProperty()).isEqualTo(serverProperty);
        assertThat(instance.getPubKeyCredParams()).isNull();
        assertThat(instance.isUserVerificationRequired()).isFalse();
        assertThat(instance.isUserPresenceRequired()).isTrue();
    }

    @Deprecated
    @Test
    void constructor_without_pubKeyCredParams_userPresenceRequired_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        RegistrationParameters instance =
                new RegistrationParameters(
                        serverProperty,
                        false
                );

        assertThat(instance.getServerProperty()).isEqualTo(serverProperty);
        assertThat(instance.getPubKeyCredParams()).isNull();
        assertThat(instance.isUserVerificationRequired()).isFalse();
        assertThat(instance.isUserPresenceRequired()).isTrue();
    }


    @Test
    void equals_hashCode_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = true;

        RegistrationParameters instanceA =
                new RegistrationParameters(
                        serverProperty,
                        null,
                        userVerificationRequired
                );
        RegistrationParameters instanceB =
                new RegistrationParameters(
                        serverProperty,
                        null,
                        userVerificationRequired
                );

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void toString_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = true;

        RegistrationParameters instance =
                new RegistrationParameters(
                        serverProperty,
                        null,
                        userVerificationRequired
                );

        //noinspection ResultOfMethodCallIgnored
        assertThatCode(instance::toString).doesNotThrowAnyException();
    }

}