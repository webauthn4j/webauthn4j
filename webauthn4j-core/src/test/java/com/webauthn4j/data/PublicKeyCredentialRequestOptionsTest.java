/*
 * Copyright 2018 the original author or authors.
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

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.CollectionUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialRequestOptionsTest {

    @Test
    void getter_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[32];
        List<PublicKeyCredentialDescriptor> allowCredentials = Collections.singletonList(
                new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        credentialId,
                        CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                )
        );

        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                allowCredentials,
                UserVerificationRequirement.DISCOURAGED,
                null
        );

        assertAll(
                () -> assertThat(credentialRequestOptions.getChallenge()).isEqualTo(challenge),
                () -> assertThat(credentialRequestOptions.getTimeout()).isEqualTo(timeout),
                () -> assertThat(credentialRequestOptions.getRpId()).isEqualTo(rpId),
                () -> assertThat(credentialRequestOptions.getAllowCredentials()).isEqualTo(allowCredentials),
                () -> assertThat(credentialRequestOptions.getUserVerification()).isEqualTo(UserVerificationRequirement.DISCOURAGED),
                () -> assertThat(credentialRequestOptions.getExtensions()).isNull()
        );
    }

    @Test
    void equals_hashCode_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[32];
        List<PublicKeyCredentialDescriptor> allowCredentials = Collections.singletonList(
                new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        credentialId,
                        CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                )
        );

        PublicKeyCredentialRequestOptions instanceA = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                allowCredentials,
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredentialRequestOptions instanceB = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                allowCredentials,
                UserVerificationRequirement.DISCOURAGED,
                null
        );

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}