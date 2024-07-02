package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.verifier.exception.IllegalBackupStateException;

public class BEBSFlagsVerifier {

    private BEBSFlagsVerifier(){}

    public static void verify(AuthenticatorData<?> authenticatorData) {
        if(!authenticatorData.isFlagBE() && authenticatorData.isFlagBS()){
            throw new IllegalBackupStateException("Backup state bit must not be set if backup eligibility bit is not set");
        }
    }
}
