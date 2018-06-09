package com.webauthn4j.authenticator;

import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AuthenticatorImplTest {

    @Test
    public void getter_setter_test() {

        AttestedCredentialData attestedCredentialData = TestUtil.createAttestedCredentialData();
        AttestationStatement attestationStatement = TestUtil.createFIDOU2FAttestationStatement();

        AuthenticatorImpl authenticator = new AuthenticatorImpl();
        authenticator.setAttestedCredentialData(attestedCredentialData);
        authenticator.setAttestationStatement(attestationStatement);
        authenticator.setCounter(1);

        assertThat(authenticator.getAttestedCredentialData()).isEqualTo(attestedCredentialData);
        assertThat(authenticator.getAttestationStatement()).isEqualTo(attestationStatement);
        assertThat(authenticator.getCounter()).isEqualTo(1);

    }

    @Test
    public void setCounter_range_test() {
        AuthenticatorImpl authenticator = new AuthenticatorImpl();
        assertThatThrownBy(() -> {
            authenticator.setCounter(-1);
        }).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> {
            authenticator.setCounter(4294967296L);
        }).isInstanceOf(IllegalArgumentException.class);
    }
}
