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

package com.webauthn4j.data;

import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.UserVerificationRequirement;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class AuthenticatorSelectionCriteriaTest {

    @Test
    void getter_test() {
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria
                = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);
        assertAll(
                () -> assertThat(authenticatorSelectionCriteria.getAuthenticatorAttachment()).isEqualTo(AuthenticatorAttachment.CROSS_PLATFORM),
                () -> assertThat(authenticatorSelectionCriteria.isRequireResidentKey()).isEqualTo(true),
                () -> assertThat(authenticatorSelectionCriteria.getUserVerification()).isEqualTo(UserVerificationRequirement.REQUIRED)
        );
    }

    @Test
    void equals_hashCode_test() {
        AuthenticatorSelectionCriteria instanceA
                = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);
        AuthenticatorSelectionCriteria instanceB
                = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED);

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}