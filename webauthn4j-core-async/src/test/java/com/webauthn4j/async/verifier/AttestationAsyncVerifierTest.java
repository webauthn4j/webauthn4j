package com.webauthn4j.async.verifier;

import com.webauthn4j.async.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.BadAaguidException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AttestationAsyncVerifierTest {

    @Test
    void verifyAAGUID_throws_BadAaguidException_for_u2f(@Mock(answer = Answers.RETURNS_DEEP_STUBS) AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        AttestationAsyncVerifier attestationAsyncVerifier = new AttestationAsyncVerifier(
                Collections.singletonList(new FIDOU2FAttestationStatementAsyncVerifier()),
                new NullCertPathTrustworthinessAsyncVerifier(),
                new NullSelfAttestationTrustworthinessAsyncVerifier());

        AttestationObject attestationObject = mock(AttestationObject.class);
        when(attestationObject.getFormat()).thenReturn(FIDOU2FAttestationStatement.FORMAT);
        when(authenticatorData.getAttestedCredentialData().getAaguid()).thenReturn(new AAGUID("fea37a71-08ce-479f-bf4b-472a93e2d17d"));
        when(attestationObject.getAuthenticatorData()).thenReturn(authenticatorData);
        assertThatThrownBy(() -> attestationAsyncVerifier.verifyAAGUID(attestationObject)).isInstanceOf(BadAaguidException.class);
    }

}