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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationRequestTest {

    @Test
    void equals_hashCode_test() {
        // Client properties
        byte[] credentialId = null /* set credentialId */;
        byte[] userHandle = null /* set userHandle */;
        byte[] authenticatorData = null /* set authenticatorData */;
        byte[] clientDataJSON = null /* set clientDataJSON */;
        String clientExtensionJSON = null /* set clientExtensionJSON */;
        byte[] signature = null /* set signature */;

        AuthenticationRequest instanceA =
                new AuthenticationRequest(
                        credentialId,
                        userHandle,
                        authenticatorData,
                        clientDataJSON,
                        clientExtensionJSON,
                        signature
                );
        AuthenticationRequest instanceB =
                new AuthenticationRequest(
                        credentialId,
                        userHandle,
                        authenticatorData,
                        clientDataJSON,
                        clientExtensionJSON,
                        signature
                );

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }


}