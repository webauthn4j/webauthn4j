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

package com.webauthn4j.verifier;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.exception.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.*;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationDataVerifierTest {

    private final AuthenticationDataVerifier target = new AuthenticationDataVerifier();

    @Test
    void verifyCredentialId_test(){
        byte[] credentialId = new byte[32];
        target.verifyCredentialId(credentialId, Collections.singletonList(credentialId));
    }

    @Test
    void verifyCredentialId_not_allowed_credential_test(){
        byte[] credentialId = new byte[32];
        List<byte[]> allowCredentials = Collections.emptyList();
        assertThatThrownBy(() -> target.verifyCredentialId(credentialId, allowCredentials)).isInstanceOf(NotAllowedCredentialIdException.class);
    }

    @Test
    void verifyAuthenticatorData_with_non_null_AttestedCredentialData(@Mock AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        AttestedCredentialData attestedCredentialData = mock(AttestedCredentialData.class);
        when(authenticatorData.getAttestedCredentialData()).thenReturn(attestedCredentialData);
        assertThatThrownBy(() -> target.verifyAuthenticatorData(authenticatorData)).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void verifyBEBSFlags_only_BSFlag_set_test() {
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], AuthenticatorData.BIT_BS, 0);
        assertThrows(IllegalBackupStateException.class,
                () -> target.verifyBEBSFlags(authenticatorData)
        );
    }

    @Test
    void verifyClientDataCrossOrigin_with_expected_crossOrigin_test() {
        target.setCrossOriginAllowed(true);
        Origin origin = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, null);
        target.verifyClientDataCrossOrigin(collectedClientData);
    }

    @Test
    void verifyClientDataCrossOrigin_with_unexpected_crossOrigin_test() {
        Origin origin = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, null);
        assertThrows(CrossOriginException.class,
                () -> target.verifyClientDataCrossOrigin(collectedClientData)
        );
    }

    @Test
    void verifyBEFlag_with_legacy_Authenticator_instance_test(){
        AuthenticatorImpl authenticator = new AuthenticatorImpl(TestDataUtil.createAttestedCredentialData(), TestAttestationStatementUtil.createBasicPackedAttestationStatement(), 0);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], BIT_UP, 3);
        assertThatCode(()-> AuthenticationDataVerifier.verifyBEFlag(authenticator, authenticatorData)).doesNotThrowAnyException();
    }

    @Test
    void verifyBEFlag_with_CredentialRecord_instance_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                true,
                true,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        byte flag = BIT_UP | BIT_BE;
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        assertThatCode(()-> AuthenticationDataVerifier.verifyBEFlag(credentialRecord, authenticatorData)).doesNotThrowAnyException();
    }

    @Test
    void verifyBEFlag_success_if_BE_flag_of_CredentialRecord_is_null_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                true,
                null,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        byte flag = BIT_UP | BIT_BE;
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        assertThatCode(()-> AuthenticationDataVerifier.verifyBEFlag(credentialRecord, authenticatorData)).doesNotThrowAnyException();
    }

    @Test
    void verifyBEFlag_throws_BadBackupEligibleFlagException_if_BE_flag_of_CredentialRecord_is_false_but_BE_flag_of_AuthenticatorData_is_true_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                true,
                false,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        byte flag = BIT_UP | BIT_BE;
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        assertThatThrownBy(()-> AuthenticationDataVerifier.verifyBEFlag(credentialRecord, authenticatorData)).isInstanceOf(BadBackupEligibleFlagException.class);
    }

    @Test
    void verifyBEFlag_throws_BadBackupEligibleFlagException_if_BE_flag_of_CredentialRecord_is_true_but_BE_flag_of_AuthenticatorData_is_false_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                true,
                true,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        byte flag = BIT_UP;
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        assertThatThrownBy(()-> AuthenticationDataVerifier.verifyBEFlag(credentialRecord, authenticatorData)).isInstanceOf(BadBackupEligibleFlagException.class);
    }

    @Test
    void verifyBEFlag_success_if_BE_flag_of_CredentialRecord_is_false_and_BE_flag_of_AuthenticatorData_is_false_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                true,
                false,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        byte flag = BIT_UP;
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        assertThatCode(()-> AuthenticationDataVerifier.verifyBEFlag(credentialRecord, authenticatorData)).doesNotThrowAnyException();
    }


    @Test
    void updateRecord_with_legacy_Authenticator_instance_test(){
        AuthenticatorImpl authenticator = new AuthenticatorImpl(TestDataUtil.createAttestedCredentialData(), TestAttestationStatementUtil.createBasicPackedAttestationStatement(), 0);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], BIT_UP, 3);
        AuthenticationDataVerifier.updateRecord(authenticator, authenticatorData);
        assertThat(authenticator.getCounter()).isEqualTo(authenticatorData.getSignCount());
    }

    @Test
    void updateRecord_with_CredentialRecord_instance_test(){
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        CredentialRecord credentialRecord = new CredentialRecordImpl(TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(), TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET), clientExtensions, Collections.singleton(AuthenticatorTransport.HYBRID));
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte)(BIT_UP | BIT_UV), 5);
        AuthenticationDataVerifier.updateRecord(credentialRecord, authenticatorData);
        assertThat(credentialRecord.getCounter()).isEqualTo(authenticatorData.getSignCount());
        assertThat(credentialRecord.isUvInitialized()).isEqualTo(authenticatorData.isFlagUV());
        assertThat(credentialRecord.isBackedUp()).isEqualTo(authenticatorData.isFlagBS());
    }

    @Test
    void updateRecord_does_not_update_uv_if_uv_of_credentialRecord_true_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                true,
                true,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        //noinspection UnnecessaryLocalVariable
        byte flag = BIT_UP; //note: BIT_UV is not included
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        AuthenticationDataVerifier.updateRecord(credentialRecord, authenticatorData);

        assertThat(credentialRecord.isUvInitialized()).isTrue();
    }

    @Test
    void updateRecord_update_uv_if_uv_of_credentialRecord_null_test(){
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationStatement,
                null,
                true,
                false,
                0,
                attestedCredentialData,
                new AuthenticationExtensionsAuthenticatorOutputs<>(),
                TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET),
                new AuthenticationExtensionsClientOutputs<>(),
                Collections.emptySet()
        );
        //noinspection UnnecessaryLocalVariable
        byte flag = BIT_UP; //note: BIT_UV is not included
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], flag, 5);
        AuthenticationDataVerifier.updateRecord(credentialRecord, authenticatorData);

        assertThat(credentialRecord.isUvInitialized()).isFalse();
    }


    @Test
    void getCustomAuthenticationVerifiers() {
        CustomAuthenticationVerifier customAuthenticationVerifier = mock(CustomAuthenticationVerifier.class);
        target.getCustomAuthenticationVerifiers().add(customAuthenticationVerifier);
        assertThat(target.getCustomAuthenticationVerifiers()).contains(customAuthenticationVerifier);
    }

    @Test
    void getter_setter_test() {
        target.setOriginVerifier(new TestOriginVerifier());
        assertThat(target.getOriginVerifier()).isInstanceOf(TestOriginVerifier.class);
        target.setCrossOriginAllowed(true);
        assertThat(target.isCrossOriginAllowed()).isTrue();
    }

    private static class TestOriginVerifier extends OriginVerifierImpl {
    }

}