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

package com.webauthn4j.attestation.authenticator;

import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for AuthenticatorData
 */
public class AuthenticatorDataTest {

    @Test
    public void flag_operation_test() {
        AuthenticatorData target;
        byte flags;

        flags = BIT_UP;
        target = new AuthenticatorData(null, flags, 0, null, null);
        assertThat(target.isFlagUP()).isTrue();
        assertThat(target.isFlagUV()).isFalse();
        assertThat(target.isFlagAT()).isFalse();
        assertThat(target.isFlagED()).isFalse();

        flags = BIT_UV;
        target = new AuthenticatorData(null, flags, 0, null, null);
        assertThat(target.isFlagUP()).isFalse();
        assertThat(target.isFlagUV()).isTrue();
        assertThat(target.isFlagAT()).isFalse();
        assertThat(target.isFlagED()).isFalse();

        flags = BIT_AT;
        target = new AuthenticatorData(null, flags, 0, null, null);
        assertThat(target.isFlagUP()).isFalse();
        assertThat(target.isFlagUV()).isFalse();
        assertThat(target.isFlagAT()).isTrue();
        assertThat(target.isFlagED()).isFalse();

        flags = BIT_ED;
        target = new AuthenticatorData(null, flags, 0, null, null);
        assertThat(target.isFlagUP()).isFalse();
        assertThat(target.isFlagUV()).isFalse();
        assertThat(target.isFlagAT()).isFalse();
        assertThat(target.isFlagED()).isTrue();
    }

    @Test
    public void equals_test() {
        AuthenticatorData instanceA = TestUtil.createAuthenticatorData();
        AuthenticatorData instanceB = TestUtil.createAuthenticatorData();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void equals_test_with_not_equal_data() {
        AuthenticatorData instanceA = new AuthenticatorData(new byte[32], BIT_UP, 0, null, null);
        AuthenticatorData instanceB = new AuthenticatorData(new byte[32], BIT_UV, 0, null, null);
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
        AuthenticatorData instanceA = new AuthenticatorData(new byte[32], BIT_UP, 0, null, null);
        AuthenticatorData instanceB = new AuthenticatorData(new byte[32], BIT_UV, 0, null, null);
        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }


}
