package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.verifier.exception.IllegalBackupStateException;

/**
 * Verifies backup eligibility and backup state flags consistency.
 * <p>
 * Implements WebAuthn Level 3 § 7.2 Step 18 (BE/BS flags verification).
 * Ensures that the BS (Backup State) bit is not set when the BE (Backup Eligible) bit is not set.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2 Verifying an Authentication Assertion</a>
 */
public class BEBSFlagsVerifier {

    private BEBSFlagsVerifier(){}

    public static void verify(AuthenticatorData<?> authenticatorData) {
        if(!authenticatorData.isFlagBE() && authenticatorData.isFlagBS()){
            throw new IllegalBackupStateException("Backup state bit must not be set if backup eligibility bit is not set");
        }
    }
}
