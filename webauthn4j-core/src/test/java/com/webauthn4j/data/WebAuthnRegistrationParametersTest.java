/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import com.webauthn4j.server.ServerProperty;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class WebAuthnRegistrationParametersTest {

    @Test
    void equals_hashCode_test(){
        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = true;

        WebAuthnRegistrationParameters instanceA =
                new WebAuthnRegistrationParameters(
                        serverProperty,
                        userVerificationRequired
                );
        WebAuthnRegistrationParameters instanceB =
                new WebAuthnRegistrationParameters(
                        serverProperty,
                        userVerificationRequired
                );

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

}