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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationParametersTest {

    @Test
    void constructor_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        Authenticator authenticator = null;

        // expectations
        boolean userVerificationRequired = true;

        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        userVerificationRequired
                );

        assertThat(authenticationParameters.getServerProperty()).isEqualTo(serverProperty);
        assertThat(authenticationParameters.getAuthenticator()).isEqualTo(authenticator);
        assertThat(authenticationParameters.isUserVerificationRequired()).isEqualTo(userVerificationRequired);
        assertThat(authenticationParameters.isUserPresenceRequired()).isTrue();
    }

    @Test
    void constructor_with_serverProperty_null_test() {
        Authenticator authenticator = TestDataUtil.createAuthenticator();
        assertThatThrownBy(()->{new AuthenticationParameters(
                null,
                authenticator,
                true,
                true
        );}).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_with_authenticator_null_test() {
        ServerProperty serverProperty = TestDataUtil.createServerProperty();
        new AuthenticationParameters(
                serverProperty,
                null,
                true,
                true
        );
    }

    @Test
    void equals_hashCode_test() {
        // Server properties
        Origin origin = Origin.create("https://example.com") /* set origin */;
        String rpId = "example.com" /* set rpId */;
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        Authenticator authenticator = null;

        // expectations
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        AuthenticationParameters instanceA =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        userVerificationRequired,
                        userPresenceRequired
                );
        AuthenticationParameters instanceB =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        userVerificationRequired,
                        userPresenceRequired
                );

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);

    }

}