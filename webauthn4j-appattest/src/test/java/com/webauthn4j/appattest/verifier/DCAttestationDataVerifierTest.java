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
import com.webauthn4j.appattest.data.DCAttestationParameters;
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
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

        assertThatCode(() -> target.verify(createDCAttestationData(authenticatorData), createDCAttestationParameters()))
                .doesNotThrowAnyException();
    }

    @Test
    void validateAuthenticatorData_with_production_invalid_aaguid_test() {
        target.setProduction(true);
        AAGUID invalidAaguid = new AAGUID("appattestdevelop".getBytes());

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(invalidAaguid, 0);
        DCAttestationData dcAttestationData = createDCAttestationData(authenticatorData);

        assertThatThrownBy(() -> target.verify(dcAttestationData, createDCAttestationParameters()))
                .isInstanceOf(BadAaguidException.class)
                .hasMessageContaining("'appattest' AAGUID is expected")
                .hasFieldOrPropertyWithValue("aaguid", invalidAaguid);
    }

    @Test
    void validateAuthenticatorData_with_development_valid_aaguid_test() {
        target.setProduction(false);
        AAGUID aaguid = new AAGUID("appattestdevelop".getBytes());

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 0);

        assertThatCode(() -> target.verify(createDCAttestationData(authenticatorData), createDCAttestationParameters()))
                .doesNotThrowAnyException();
    }

    @Test
    void validateAuthenticatorData_with_development_invalid_aaguid_test() {
        target.setProduction(false);
        AAGUID invalidAaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(invalidAaguid, 0);
        DCAttestationData dcAttestationData = createDCAttestationData(authenticatorData);

        assertThatThrownBy(() -> target.verify(dcAttestationData, createDCAttestationParameters()))
                .isInstanceOf(BadAaguidException.class)
                .hasMessageContaining("'appattestdevelop' AAGUID is expected")
                .hasFieldOrPropertyWithValue("aaguid", invalidAaguid);
    }

    @Test
    void validateAuthenticatorData_with_non_zero_counter_test() {
        target.setProduction(true);
        AAGUID aaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 1);
        DCAttestationData dcAttestationData = createDCAttestationData(authenticatorData);

        assertThatThrownBy(() -> target.verify(dcAttestationData, createDCAttestationParameters()))
                .isInstanceOf(MaliciousCounterValueException.class)
                .hasMessageContaining("Counter is not zero");
    }

    @Test
    void validateKeyId_with_mismatched_keyId_and_credentialId_test() {
        target.setProduction(true);
        AAGUID aaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());

        byte[] keyId = new byte[]{1, 2, 3, 4};
        byte[] credentialId = new byte[]{5, 6, 7, 8};

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 0, credentialId);
        DCAttestationData dcAttestationData = createDCAttestationDataWithKeyId(authenticatorData, keyId);

        assertThatThrownBy(() -> target.verify(dcAttestationData, createDCAttestationParameters()))
                .isInstanceOf(BadAttestationStatementException.class)
                .hasMessageContaining("key identifier doesn't match credentialId");
    }

    @Test
    void validateKeyId_with_matched_keyId_and_credentialId_test() {
        target.setProduction(true);
        AAGUID aaguid = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());

        byte[] keyIdAndCredentialId = new byte[]{1, 2, 3, 4};

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = createAuthenticatorData(aaguid, 0, keyIdAndCredentialId);

        assertThatCode(() -> target.verify(createDCAttestationDataWithKeyId(authenticatorData, keyIdAndCredentialId), createDCAttestationParameters()))
                .doesNotThrowAnyException();
    }

    private AuthenticatorData<RegistrationExtensionAuthenticatorOutput> createAuthenticatorData(AAGUID aaguid, long signCount) {
        return createAuthenticatorData(aaguid, signCount, new byte[]{1, 2, 3, 4});
    }

    @SuppressWarnings("unchecked")
    private AuthenticatorData<RegistrationExtensionAuthenticatorOutput> createAuthenticatorData(AAGUID aaguid, long signCount, byte[] credentialId) {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = mock(AuthenticatorData.class);
        AttestedCredentialData attestedCredentialData = mock(AttestedCredentialData.class);
        COSEKey coseKey = mock(COSEKey.class);

        when(authenticatorData.getSignCount()).thenReturn(signCount);
        when(authenticatorData.getAttestedCredentialData()).thenReturn(attestedCredentialData);
        when(attestedCredentialData.getAaguid()).thenReturn(aaguid);
        when(attestedCredentialData.getCredentialId()).thenReturn(credentialId);
        when(attestedCredentialData.getCOSEKey()).thenReturn(coseKey);

        return authenticatorData;
    }

    private DCAttestationData createDCAttestationData(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        return createDCAttestationDataWithKeyId(authenticatorData, authenticatorData.getAttestedCredentialData().getCredentialId());
    }

    @SuppressWarnings("unchecked")
    private DCAttestationData createDCAttestationDataWithKeyId(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData, byte[] keyId) {
        DCAttestationData dcAttestationData = mock(DCAttestationData.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        AttestationStatement attestationStatement = mock(AppleAppAttestAttestationStatement.class);
        AttestationCertificatePath x5c = mock(AttestationCertificatePath.class);

        when(dcAttestationData.getKeyId()).thenReturn(keyId);
        when(dcAttestationData.getAttestationObject()).thenReturn(attestationObject);
        when(dcAttestationData.getAttestationObjectBytes()).thenReturn(new byte[0]);
        when(dcAttestationData.getClientDataHash()).thenReturn(new byte[32]);
        when(attestationObject.getAuthenticatorData()).thenReturn(authenticatorData);
        when(attestationObject.getAttestationStatement()).thenReturn(attestationStatement);
        when(attestationStatement.getFormat()).thenReturn("apple-appattest");
        when(((AppleAppAttestAttestationStatement) attestationStatement).getX5c()).thenReturn(x5c);
        when(x5c.isEmpty()).thenReturn(false);

        return dcAttestationData;
    }

    private DCAttestationParameters createDCAttestationParameters() {
        DCServerProperty dcServerProperty = new DCServerProperty("example.com", new DefaultChallenge());
        return new DCAttestationParameters(dcServerProperty);
    }
}
