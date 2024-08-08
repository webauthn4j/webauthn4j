package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.IllegalBackupStateException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class BEBSFlagsVerifierTest {

    @Test
    void verify_registration_AuthenticatorData_only_BSFlag_set_test() {
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], AuthenticatorData.BIT_BS, 0);
        assertThrows(IllegalBackupStateException.class,
                () -> BEBSFlagsVerifier.verify(authenticatorData)
        );
    }

    @Test
    void verify_authentication_AuthenticatorData_only_BSFlag_set_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], AuthenticatorData.BIT_BS, 0);
        assertThrows(IllegalBackupStateException.class,
                () -> BEBSFlagsVerifier.verify(authenticatorData)
        );
    }
}
