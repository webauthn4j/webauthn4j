package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import com.webauthn4j.verifier.exception.NotAllowedCredentialIdException;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialIdVerifierTest {

    @Test
    void verify_test(){
        byte[] credentialId = new byte[32];
        CredentialIdVerifier.verify(credentialId, Collections.singletonList(credentialId));
    }

    @Test
    void verify_not_allowed_credential_test(){
        byte[] credentialId = new byte[32];
        List<byte[]> allowCredentials = Collections.emptyList();
        assertThatThrownBy(() -> CredentialIdVerifier.verify(credentialId, allowCredentials)).isInstanceOf(NotAllowedCredentialIdException.class);
    }




}