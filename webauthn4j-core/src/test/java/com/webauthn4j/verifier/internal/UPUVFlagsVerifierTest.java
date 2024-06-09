package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.UserNotPresentException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class UPUVFlagsVerifierTest {

    @Test
    void verify_not_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        UPUVFlagsVerifier.verify(authenticatorData, false, false);
    }

    @Test
    void verify_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) (AuthenticatorData.BIT_UP | AuthenticatorData.BIT_UV), 0);
        UPUVFlagsVerifier.verify(authenticatorData, true, true);
    }

    @Test
    void verify_UserNotVerifiedException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(UserNotVerifiedException.class,
                () -> UPUVFlagsVerifier.verify(authenticatorData, false, true)
        );
    }

    @Test
    void verify_UserNotPresentException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(UserNotPresentException.class,
                () -> UPUVFlagsVerifier.verify(authenticatorData, true, false)
        );
    }


}