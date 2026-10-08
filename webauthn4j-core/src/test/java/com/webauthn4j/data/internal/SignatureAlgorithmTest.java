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

package com.webauthn4j.data.internal;

import com.webauthn4j.data.MessageDigestAlgorithm;
import com.webauthn4j.data.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class SignatureAlgorithmTest {


    @Test
    void getJcaName_test() {
        assertThat(SignatureAlgorithm.RS256.getJcaName()).isEqualTo("SHA256withRSA");
    }

    @Test
    void getMessageDigestAlgorithm_test() {
        assertThat(SignatureAlgorithm.RS256.getMessageDigestAlgorithm()).isEqualTo(MessageDigestAlgorithm.SHA256);
    }

    @Test
    void getMessageDigestAlgorithm_pure_signature_scheme_returns_null_test() {
        assertThat(SignatureAlgorithm.Ed25519.getMessageDigestAlgorithm()).isNull();
        assertThat(SignatureAlgorithm.ML_DSA_44.getMessageDigestAlgorithm()).isNull();
        assertThat(SignatureAlgorithm.ML_DSA_65.getMessageDigestAlgorithm()).isNull();
        assertThat(SignatureAlgorithm.ML_DSA_87.getMessageDigestAlgorithm()).isNull();
    }

    @Test
    void equals_hashCode_test() {
        assertThat(SignatureAlgorithm.ES256)
                .isEqualTo(SignatureAlgorithm.ES256)
                .hasSameHashCodeAs(SignatureAlgorithm.ES256)
                .isNotEqualTo(SignatureAlgorithm.RS512)
                .isNotEqualTo(SignatureAlgorithm.ES512);
    }

    @Test
    void equals_hashCode_pure_signature_scheme_test() {
        assertThat(SignatureAlgorithm.Ed25519)
                .isEqualTo(SignatureAlgorithm.Ed25519)
                .hasSameHashCodeAs(SignatureAlgorithm.Ed25519)
                .isNotEqualTo(SignatureAlgorithm.ES256);
    }
}