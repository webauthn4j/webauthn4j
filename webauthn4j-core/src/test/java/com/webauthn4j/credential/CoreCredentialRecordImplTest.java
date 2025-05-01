package com.webauthn4j.credential;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class CoreCredentialRecordImplTest {

    private AttestationObject attestationObject;
    private AttestationStatement attestationStatement;
    private Boolean flagUV;
    private Boolean flagBE;
    private Boolean flagBS;
    private long signCount;
    private AttestedCredentialData attestedCredentialData;
    private AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> extensions;

    @BeforeEach
    void setUp() {
        attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
        
        attestationStatement = attestationObject.getAttestationStatement();
        flagUV = authenticatorData.isFlagUV();
        flagBE = authenticatorData.isFlagBE();
        flagBS = authenticatorData.isFlagBS();
        signCount = authenticatorData.getSignCount();
        attestedCredentialData = authenticatorData.getAttestedCredentialData();
        extensions = authenticatorData.getExtensions();
    }

    @Test
    void shouldCreateCoreCredentialRecordWithExplicitParameters() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationStatement,
                flagUV,
                flagBE,
                flagBS,
                signCount,
                attestedCredentialData,
                extensions
        );

        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isEqualTo(flagUV),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isEqualTo(flagBE),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isEqualTo(flagBS),
                () -> assertThat(coreCredentialRecord.getAttestedCredentialData()).isEqualTo(attestedCredentialData),
                () -> assertThat(coreCredentialRecord.getAttestationStatement()).isEqualTo(attestationStatement),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(signCount)
        );
    }

    @Test
    void shouldCreateCoreCredentialRecordFromAttestationObject() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(attestationObject);

        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isEqualTo(flagUV),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isEqualTo(flagBE),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isEqualTo(flagBS),
                () -> assertThat(coreCredentialRecord.getAttestedCredentialData()).isEqualTo(attestedCredentialData),
                () -> assertThat(coreCredentialRecord.getAttestationStatement()).isEqualTo(attestationStatement),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(signCount)
        );
    }

    @Test
    void shouldUpdatePropertiesViaSetters() {
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(attestationObject);

        coreCredentialRecord.setUvInitialized(true);
        coreCredentialRecord.setBackupEligible(true);
        coreCredentialRecord.setBackedUp(true);
        coreCredentialRecord.setCounter(100);

        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isTrue(),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isTrue(),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isTrue(),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(100)
        );
    }

    @Test
    void shouldBeEqualWhenConstructedFromSameAttestationObject() {
        CoreCredentialRecord instanceA = new CoreCredentialRecordImpl(attestationObject);
        CoreCredentialRecord instanceB = new CoreCredentialRecordImpl(attestationObject);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }
}