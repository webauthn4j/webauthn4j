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

import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test for AuthenticatorData
 */
class AuthenticatorDataTest {

    @Test
    void flag_operation_test() {
        // Given
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> target1 = new AuthenticatorData<>(new byte[32], BIT_UP, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> target2 = new AuthenticatorData<>(new byte[32], BIT_UV, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> target3 = new AuthenticatorData<>(new byte[32], BIT_AT, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> target4 = new AuthenticatorData<>(new byte[32], BIT_ED, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> target5 = new AuthenticatorData<>(new byte[32], BIT_BE, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> target6 = new AuthenticatorData<>(new byte[32], BIT_BS, 0);

        // When
        // Then
        assertAll(
                () -> assertThat(target1.isFlagUP()).isTrue(),
                () -> assertThat(target1.isFlagUV()).isFalse(),
                () -> assertThat(target1.isFlagAT()).isFalse(),
                () -> assertThat(target1.isFlagED()).isFalse(),
                () -> assertThat(target1.isFlagBE()).isFalse(),
                () -> assertThat(target1.isFlagBS()).isFalse(),

                () -> assertThat(target2.isFlagUP()).isFalse(),
                () -> assertThat(target2.isFlagUV()).isTrue(),
                () -> assertThat(target2.isFlagAT()).isFalse(),
                () -> assertThat(target2.isFlagED()).isFalse(),
                () -> assertThat(target2.isFlagBE()).isFalse(),
                () -> assertThat(target2.isFlagBS()).isFalse(),

                () -> assertThat(target3.isFlagUP()).isFalse(),
                () -> assertThat(target3.isFlagUV()).isFalse(),
                () -> assertThat(target3.isFlagAT()).isTrue(),
                () -> assertThat(target3.isFlagED()).isFalse(),
                () -> assertThat(target3.isFlagBE()).isFalse(),
                () -> assertThat(target3.isFlagBS()).isFalse(),

                () -> assertThat(target4.isFlagUP()).isFalse(),
                () -> assertThat(target4.isFlagUV()).isFalse(),
                () -> assertThat(target4.isFlagAT()).isFalse(),
                () -> assertThat(target4.isFlagED()).isTrue(),
                () -> assertThat(target4.isFlagBE()).isFalse(),
                () -> assertThat(target4.isFlagBS()).isFalse(),

                () -> assertThat(target5.isFlagUP()).isFalse(),
                () -> assertThat(target5.isFlagUV()).isFalse(),
                () -> assertThat(target5.isFlagAT()).isFalse(),
                () -> assertThat(target5.isFlagED()).isFalse(),
                () -> assertThat(target5.isFlagBE()).isTrue(),
                () -> assertThat(target5.isFlagBS()).isFalse(),

                () -> assertThat(target6.isFlagUP()).isFalse(),
                () -> assertThat(target6.isFlagUV()).isFalse(),
                () -> assertThat(target6.isFlagAT()).isFalse(),
                () -> assertThat(target6.isFlagED()).isFalse(),
                () -> assertThat(target6.isFlagBE()).isFalse(),
                () -> assertThat(target6.isFlagBS()).isTrue()

        );
    }

    @Test
    void equals_test() {
        // Given
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceA = TestDataUtil.createAuthenticatorData();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceB = TestDataUtil.createAuthenticatorData();

        // When
        // Then
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    void equals_test_with_not_equal_data() {
        // Given
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceA = new AuthenticatorData<>(new byte[32], BIT_UP, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceB = new AuthenticatorData<>(new byte[32], BIT_UV, 0);

        // When
        // Then
        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    void hashCode_test() {
        // Given
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceA = TestDataUtil.createAuthenticatorData();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceB = TestDataUtil.createAuthenticatorData();

        // When
        // Then
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

    @Test
    void hashCode_test_with_not_equal_data() {
        // Given
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceA = new AuthenticatorData<>(new byte[32], BIT_UP, 0);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> instanceB = new AuthenticatorData<>(new byte[32], BIT_UV, 0);

        // When
        // Then
        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }
}