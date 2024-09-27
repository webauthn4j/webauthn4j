package com.webauthn4j.verifier.internal;

import com.webauthn4j.verifier.exception.CredentialIdTooLongException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class CredentialIdLengthVerifierTest {

    @Test
    void verify_too_long_credentialId_test(){
        assertThrows(CredentialIdTooLongException.class,
                () -> CredentialIdLengthVerifier.verify(new byte[1024], 1023)
        );
    }
}
