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

package com.webauthn4j.webauthn.context.validator.attestation.authenticator;

import com.webauthn4j.test.CoreTestUtil;
import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for WebAuthnAuthenticatorData
 */
public class WebAuthnAuthenticatorDataTest {

    @Test
    public void flag_operation_test() {
        WebAuthnAuthenticatorData target = new WebAuthnAuthenticatorData();
        target.setFlagUP(true);
        assertThat(target.isFlagUP()).isTrue();
        target.setFlagUV(true);
        assertThat(target.isFlagUV()).isTrue();
        target.setFlagAT(true);
        assertThat(target.isFlagAT()).isTrue();
        target.setFlagED(true);
        assertThat(target.isFlagED()).isTrue();

        target.setFlagUP(false);
        assertThat(target.isFlagUP()).isFalse();
        target.setFlagUV(false);
        assertThat(target.isFlagUV()).isFalse();
        target.setFlagAT(false);
        assertThat(target.isFlagAT()).isFalse();
        target.setFlagED(false);
        assertThat(target.isFlagED()).isFalse();
    }

    @Test
    public void equals_test() {
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void equals_test_with_not_equal_data() {
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        instanceA.setFlagUP(false);
        instanceB.setFlagUP(true);
        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    public void hashCode_test() {
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        assertThat(instanceA.hashCode()).isEqualTo(instanceB.hashCode());
    }

    @Test
    public void hashCode_test_with_not_equal_data() {
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        instanceA.setCounter(1);
        instanceB.setCounter(2);
        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }


}
