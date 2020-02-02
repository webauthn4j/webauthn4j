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

package com.webauthn4j.data.attestation.statement;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class SignatureAlgorithmTest {

    @Test
    void create_with_invalid_alg_test() {
        assertThatThrownBy(() -> SignatureAlgorithm.create(new COSEAlgorithmIdentifier(-16))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getJcaName_test() {
        assertThat(SignatureAlgorithm.RS256.getJcaName()).isEqualTo("SHA256withRSA");
    }

    @Test
    void getMessageDigestJcaName_test() {
        assertThat(SignatureAlgorithm.RS256.getMessageDigestJcaName()).isEqualTo("SHA-256");
    }

    @Test
    void equals_hashCode_test() {
        assertThat(SignatureAlgorithm.ES256).isEqualTo(SignatureAlgorithm.ES256);
        assertThat(SignatureAlgorithm.ES256).hasSameHashCodeAs(SignatureAlgorithm.ES256);
        assertThat(SignatureAlgorithm.ES256).isNotEqualTo(SignatureAlgorithm.RS512);
        assertThat(SignatureAlgorithm.ES256).isNotEqualTo(SignatureAlgorithm.ES512);
    }
}