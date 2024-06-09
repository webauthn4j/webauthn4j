package com.webauthn4j.verifier.internal;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.exception.BadBackupEligibleFlagException;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_BE;
import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BEFlagVerifierTest {

    @Test
    void verify_with_legacy_Authenticator_instance_test(){
        AuthenticatorImpl authenticator = new AuthenticatorImpl(TestDataUtil.createAttestedCredentialData(), TestAttestationStatementUtil.createBasicPackedAttestationStatement(), 0);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], BIT_UP, 3);
        assertThatCode(()-> BEFlagVerifier.verify(authenticator, authenticatorData)).doesNotThrowAnyException();
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
        assertThatCode(()-> BEFlagVerifier.verify(credentialRecord, authenticatorData)).doesNotThrowAnyException();
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
        assertThatCode(()-> BEFlagVerifier.verify(credentialRecord, authenticatorData)).doesNotThrowAnyException();
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
        assertThatThrownBy(()-> BEFlagVerifier.verify(credentialRecord, authenticatorData)).isInstanceOf(BadBackupEligibleFlagException.class);
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
        assertThatThrownBy(()-> BEFlagVerifier.verify(credentialRecord, authenticatorData)).isInstanceOf(BadBackupEligibleFlagException.class);
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
        assertThatCode(()-> BEFlagVerifier.verify(credentialRecord, authenticatorData)).doesNotThrowAnyException();
    }
}
