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

package com.webauthn4j.response.attestation.authenticator;

import com.webauthn4j.test.TestUtil;
import org.junit.jupiter.api.Test;

import static com.webauthn4j.response.attestation.authenticator.AuthenticatorData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test for AuthenticatorData
 */
public class AuthenticatorDataTest {

    @Test
    public void flag_operation_test() {
        AuthenticatorData target1 = new AuthenticatorData(null, BIT_UP, 0);
        AuthenticatorData target2 = new AuthenticatorData(null, BIT_UV, 0);
        AuthenticatorData target3 = new AuthenticatorData(null, BIT_AT, 0);
        AuthenticatorData target4 = new AuthenticatorData(null, BIT_ED, 0);

        assertAll(
                () -> assertThat(target1.isFlagUP()).isTrue(),
                () -> assertThat(target1.isFlagUV()).isFalse(),
                () -> assertThat(target1.isFlagAT()).isFalse(),
                () -> assertThat(target1.isFlagED()).isFalse(),

                () -> assertThat(target2.isFlagUP()).isFalse(),
                () -> assertThat(target2.isFlagUV()).isTrue(),
                () -> assertThat(target2.isFlagAT()).isFalse(),
                () -> assertThat(target2.isFlagED()).isFalse(),

                () -> assertThat(target3.isFlagUP()).isFalse(),
                () -> assertThat(target3.isFlagUV()).isFalse(),
                () -> assertThat(target3.isFlagAT()).isTrue(),
                () -> assertThat(target3.isFlagED()).isFalse(),

                () -> assertThat(target4.isFlagUP()).isFalse(),
                () -> assertThat(target4.isFlagUV()).isFalse(),
                () -> assertThat(target4.isFlagAT()).isFalse(),
                () -> assertThat(target4.isFlagED()).isTrue()
        );
    }

    @Test
    public void equals_test() {
        AuthenticatorData instanceA = TestUtil.createAuthenticatorData();
        AuthenticatorData instanceB = TestUtil.createAuthenticatorData();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void equals_test_with_not_equal_data() {
        AuthenticatorData instanceA = new AuthenticatorData(new byte[32], BIT_UP, 0);
        AuthenticatorData instanceB = new AuthenticatorData(new byte[32], BIT_UV, 0);
        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    public void hashCode_test() {
        AuthenticatorData instanceA = TestUtil.createAuthenticatorData();
        AuthenticatorData instanceB = TestUtil.createAuthenticatorData();
        assertThat(instanceA.hashCode()).isEqualTo(instanceB.hashCode());
    }

    @Test
    public void hashCode_test_with_not_equal_data() {
        AuthenticatorData instanceA = new AuthenticatorData(new byte[32], BIT_UP, 0);
        AuthenticatorData instanceB = new AuthenticatorData(new byte[32], BIT_UV, 0);
        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }
}
