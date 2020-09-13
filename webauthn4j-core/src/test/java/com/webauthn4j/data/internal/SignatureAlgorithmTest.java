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
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


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
    void equals_hashCode_test() {
        assertThat(SignatureAlgorithm.ES256).isEqualTo(SignatureAlgorithm.ES256);
        assertThat(SignatureAlgorithm.ES256).hasSameHashCodeAs(SignatureAlgorithm.ES256);
        assertThat(SignatureAlgorithm.ES256).isNotEqualTo(SignatureAlgorithm.RS512);
        assertThat(SignatureAlgorithm.ES256).isNotEqualTo(SignatureAlgorithm.ES512);
    }
}