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

package com.webauthn4j.data;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.CollectionUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class AuthenticatorAttestationResponseTest {

    private ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void easilyAccessingCredentialData_test(){
        byte[] clientDataJSONBytes = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        byte[] attestationObjectBytes = objectConverter.getCborConverter().writeValueAsBytes(attestationObject);
        AuthenticatorAttestationResponse instance = new AuthenticatorAttestationResponse(clientDataJSONBytes, attestationObjectBytes);
        byte[] authenticatorData = instance.getAuthenticatorData();
        byte[] publicKey = instance.getPublicKey();
        COSEAlgorithmIdentifier publicKeyAlgorithm = instance.getPublicKeyAlgorithm();
        assertThat(authenticatorData).isEqualTo(new AuthenticatorDataConverter(objectConverter).convert(attestationObject.getAuthenticatorData()));
        assertThat(publicKey).isEqualTo(attestationObject.getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getPublicKey().getEncoded());
        assertThat(publicKeyAlgorithm).isEqualTo(attestationObject.getAuthenticatorData().getAttestedCredentialData().getCOSEKey().getAlgorithm());
    }

    @Test
    void equals_hashCode_test() {
        AuthenticatorAttestationResponse instanceA = new AuthenticatorAttestationResponse(new byte[0], new byte[1]);
        AuthenticatorAttestationResponse instanceB = new AuthenticatorAttestationResponse(new byte[0], new byte[1]);

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void getTransports_test() {
        AuthenticatorAttestationResponse target;
        target = new AuthenticatorAttestationResponse(new byte[0], new byte[0], CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB));
        assertThat(target.getTransports()).containsExactly(AuthenticatorTransport.USB);

        target = new AuthenticatorAttestationResponse(new byte[0], new byte[0]);
        assertThat(target.getTransports()).isEmpty();
    }
}
