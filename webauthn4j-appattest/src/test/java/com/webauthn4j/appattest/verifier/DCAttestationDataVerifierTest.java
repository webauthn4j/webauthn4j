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

package com.webauthn4j.appattest.verifier;

import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.BadAaguidException;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DCAttestationDataVerifierTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final DCAttestationDataVerifier target = new DCAttestationDataVerifier(
            new NullCertPathTrustworthinessVerifier(),
            Collections.emptyList(),
            objectConverter
    );

    @Test
    void validateAuthenticatorData_with_production_valid_aaguid_test() {
        target.setProduction(true);
        AAGUID aaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());
        
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 0);
        
        assertThatCode(() -> target.validateAuthenticatorData(authenticatorData))
                .doesNotThrowAnyException();
    }

    @Test
    void validateAuthenticatorData_with_production_invalid_aaguid_test() {
        target.setProduction(true);
        AAGUID invalidAaguid = new AAGUID("appattestdevelop".getBytes());
        
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(invalidAaguid, 0);
        
        assertThatThrownBy(() -> target.validateAuthenticatorData(authenticatorData))
                .isInstanceOf(BadAaguidException.class)
                .hasMessageContaining("'appattest' AAGUID is expected")
                .hasFieldOrPropertyWithValue("aaguid", invalidAaguid);
    }

    @Test
    void validateAuthenticatorData_with_development_valid_aaguid_test() {
        target.setProduction(false);
        AAGUID aaguid = new AAGUID("appattestdevelop".getBytes());
        
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 0);
        
        assertThatCode(() -> target.validateAuthenticatorData(authenticatorData))
                .doesNotThrowAnyException();
    }

    @Test
    void validateAuthenticatorData_with_development_invalid_aaguid_test() {
        target.setProduction(false);
        AAGUID invalidAaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());
        
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(invalidAaguid, 0);
        
        assertThatThrownBy(() -> target.validateAuthenticatorData(authenticatorData))
                .isInstanceOf(BadAaguidException.class)
                .hasMessageContaining("'appattestdevelop' AAGUID is expected")
                .hasFieldOrPropertyWithValue("aaguid", invalidAaguid);
    }

    @Test
    void validateAuthenticatorData_with_non_zero_counter_test() {
        target.setProduction(true);
        AAGUID aaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());
        
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 1);
        
        assertThatThrownBy(() -> target.validateAuthenticatorData(authenticatorData))
                .isInstanceOf(MaliciousCounterValueException.class)
                .hasMessageContaining("Counter is not zero");
    }

    @Test
    void validateKeyId_with_mismatched_keyId_and_credentialId_test() {
        byte[] keyId = new byte[]{1, 2, 3, 4};
        byte[] credentialId = new byte[]{5, 6, 7, 8};
        
        DCAttestationData dcAttestationData = createDCAttestationDataWithKeyId(keyId, credentialId);
        
        assertThatThrownBy(() -> target.validateKeyId(dcAttestationData))
                .isInstanceOf(BadAttestationStatementException.class)
                .hasMessageContaining("key identifier doesn't match credentialId");
    }

    @Test
    void validateKeyId_with_matched_keyId_and_credentialId_test() {
        byte[] keyIdAndCredentialId = new byte[]{1, 2, 3, 4};
        
        DCAttestationData dcAttestationData = createDCAttestationDataWithKeyId(keyIdAndCredentialId, keyIdAndCredentialId);
        
        assertThatCode(() -> target.validateKeyId(dcAttestationData))
                .doesNotThrowAnyException();
    }

    @SuppressWarnings("unchecked")
    private AuthenticatorData<RegistrationExtensionAuthenticatorOutput> createAuthenticatorData(AAGUID aaguid, long signCount) {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = mock(AuthenticatorData.class);
        AttestedCredentialData attestedCredentialData = mock(AttestedCredentialData.class);

        when(authenticatorData.getSignCount()).thenReturn(signCount);
        when(authenticatorData.getAttestedCredentialData()).thenReturn(attestedCredentialData);
        when(attestedCredentialData.getAaguid()).thenReturn(aaguid);

        return authenticatorData;
    }

    @SuppressWarnings("unchecked")
    private DCAttestationData createDCAttestationDataWithKeyId(byte[] keyId, byte[] credentialId) {
        DCAttestationData dcAttestationData = mock(DCAttestationData.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = mock(AuthenticatorData.class);
        AttestedCredentialData attestedCredentialData = mock(AttestedCredentialData.class);

        when(dcAttestationData.getKeyId()).thenReturn(keyId);
        when(dcAttestationData.getAttestationObject()).thenReturn(attestationObject);
        when(attestationObject.getAuthenticatorData()).thenReturn(authenticatorData);
        when(authenticatorData.getAttestedCredentialData()).thenReturn(attestedCredentialData);
        when(attestedCredentialData.getCredentialId()).thenReturn(credentialId);

        return dcAttestationData;
    }
}
