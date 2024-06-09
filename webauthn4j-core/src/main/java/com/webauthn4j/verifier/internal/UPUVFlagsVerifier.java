package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.verifier.exception.UserNotPresentException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;

public class UPUVFlagsVerifier {

    private UPUVFlagsVerifier(){}

    public static void verify(AuthenticatorData<?> authenticatorData, boolean isUserPresenceRequired, boolean isUserVerificationRequired) {
        //spec| Step14
        //spec| Verify that the User Present bit of the flags in authData is set.
        //      Administrator can allow UP=false condition
        if (isUserPresenceRequired && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Verifier is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        //spec| Step15
        //spec| If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        if (isUserVerificationRequired && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Verifier is configured to check user verified, but UV flag in authenticatorData is not set.");
        }
    }
}
