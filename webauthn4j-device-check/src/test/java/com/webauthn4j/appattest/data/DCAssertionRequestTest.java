/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.appattest.data;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DCAssertionRequestTest {

    @Test
    void equals_hashCode_test() {

        byte[] credentialId = new byte[24];
        byte[] assertion = new byte[64];
        byte[] clientDataHash = new byte[32];
        DCAssertionRequest instanceA = new DCAssertionRequest(credentialId, assertion, clientDataHash);
        DCAssertionRequest instanceB = new DCAssertionRequest(credentialId, assertion, clientDataHash);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

}