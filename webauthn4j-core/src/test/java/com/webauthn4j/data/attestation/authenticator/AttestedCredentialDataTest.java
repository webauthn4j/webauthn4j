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

package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Created by ynojima on 2017/08/19.
 */
class AttestedCredentialDataTest {

    /**
     * AttestedCredentialData must have default constructor
     */
    @Test
    void constructor_test() {
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        assertAll(
                () -> assertThat(attestedCredentialData.getCredentialId()).isNotNull(),
                () -> assertThat(attestedCredentialData.getAaguid()).isNotNull(),
                () -> assertThat(attestedCredentialData.getCOSEKey()).isNotNull()
        );
    }

    @Test
    void equals_hashCode_test() {
        AttestedCredentialData instanceA = TestDataUtil.createAttestedCredentialData();
        AttestedCredentialData instanceB = TestDataUtil.createAttestedCredentialData();
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
