package com.webauthn4j.credential;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class CoreCredentialRecordImplTest {

    @Test
    void constructor_test() {
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(
                attestationObject.getAttestationStatement(),
                attestationObject.getAuthenticatorData().isFlagUV(),
                attestationObject.getAuthenticatorData().isFlagBE(),
                attestationObject.getAuthenticatorData().isFlagBS(),
                attestationObject.getAuthenticatorData().getSignCount(),
                attestationObject.getAuthenticatorData().getAttestedCredentialData(),
                attestationObject.getAuthenticatorData().getExtensions()
                );

        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isEqualTo(attestationObject.getAuthenticatorData().isFlagUV()),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isEqualTo(attestationObject.getAuthenticatorData().isFlagBE()),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isEqualTo(attestationObject.getAuthenticatorData().isFlagBS()),
                () -> assertThat(coreCredentialRecord.getAttestedCredentialData()).isEqualTo(attestationObject.getAuthenticatorData().getAttestedCredentialData()),
                () -> assertThat(coreCredentialRecord.getAttestationStatement()).isEqualTo(attestationObject.getAttestationStatement()),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(attestationObject.getAuthenticatorData().getSignCount())
        );
    }

    @Test
    void getter_test() {
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        CoreCredentialRecord coreCredentialRecord = new CoreCredentialRecordImpl(attestationObject);

        assertAll(
                () -> assertThat(coreCredentialRecord.isUvInitialized()).isEqualTo(attestationObject.getAuthenticatorData().isFlagUV()),
                () -> assertThat(coreCredentialRecord.isBackupEligible()).isEqualTo(attestationObject.getAuthenticatorData().isFlagBE()),
                () -> assertThat(coreCredentialRecord.isBackedUp()).isEqualTo(attestationObject.getAuthenticatorData().isFlagBS()),
                () -> assertThat(coreCredentialRecord.getAttestedCredentialData()).isEqualTo(attestationObject.getAuthenticatorData().getAttestedCredentialData()),
                () -> assertThat(coreCredentialRecord.getAttestationStatement()).isEqualTo(attestationObject.getAttestationStatement()),
                () -> assertThat(coreCredentialRecord.getCounter()).isEqualTo(attestationObject.getAuthenticatorData().getSignCount())
        );
    }

    @Test
    void setter_test() {
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
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
    void equals_hashCode_test() {
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        CoreCredentialRecord instanceA = new CoreCredentialRecordImpl(attestationObject);
        CoreCredentialRecord instanceB = new CoreCredentialRecordImpl(attestationObject);

        assertThat(instanceA).isEqualTo(instanceB).hasSameHashCodeAs(instanceB);
    }

}