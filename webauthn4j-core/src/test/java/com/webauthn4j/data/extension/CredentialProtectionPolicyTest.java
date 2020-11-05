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

package com.webauthn4j.data.extension;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialProtectionPolicyTest {

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test
    void create_test() {
        assertThat(CredentialProtectionPolicy.create((byte) 0x01)).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat(CredentialProtectionPolicy.create((byte) 0x02)).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST);
        assertThat(CredentialProtectionPolicy.create((byte) 0x03)).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);

        assertThatThrownBy(() -> CredentialProtectionPolicy.create((byte) 0x00)).isInstanceOf(IllegalArgumentException.class);

        assertThat(CredentialProtectionPolicy.create("userVerificationOptional")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat(CredentialProtectionPolicy.create("userVerificationOptionalWithCredentialIDList")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST);
        assertThat(CredentialProtectionPolicy.create("userVerificationRequired")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);

        assertThatThrownBy(() -> CredentialProtectionPolicy.create("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toString_toByte_test() {
        assertThat(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL.toByte()).isEqualTo((byte) 0x01);
        assertThat(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL.toString()).hasToString("userVerificationOptional");
    }

}