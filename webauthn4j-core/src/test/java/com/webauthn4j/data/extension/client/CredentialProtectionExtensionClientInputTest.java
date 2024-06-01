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

package com.webauthn4j.data.extension.client;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class CredentialProtectionExtensionClientInputTest {

    @Test
    void getIdentifier_test() {
        CredentialProtectionExtensionClientInput target = new CredentialProtectionExtensionClientInput(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, true);
        assertThat(target.getIdentifier()).isEqualTo(CredentialProtectionExtensionClientInput.ID);
    }

    @Test
    void getValue_with_valid_key_test() {
        CredentialProtectionExtensionClientInput target = new CredentialProtectionExtensionClientInput(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, true);
        assertThatCode(() -> target.getValue("credentialProtectionPolicy")).doesNotThrowAnyException();
        assertThatCode(() -> target.getValue("enforceCredentialProtectionPolicy")).doesNotThrowAnyException();
    }

    @Test
    void getValue_with_invalid_key_test() {
        CredentialProtectionExtensionClientInput target = new CredentialProtectionExtensionClientInput(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, true);
        assertThatThrownBy(() -> target.getValue("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validate_test() {
        CredentialProtectionExtensionClientInput target = new CredentialProtectionExtensionClientInput(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST);
        assertThatCode(target::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_invalid_data_test() {
        CredentialProtectionExtensionClientInput target = new CredentialProtectionExtensionClientInput(null);
        assertThatThrownBy(target::validate).isInstanceOf(ConstraintViolationException.class);
    }

}