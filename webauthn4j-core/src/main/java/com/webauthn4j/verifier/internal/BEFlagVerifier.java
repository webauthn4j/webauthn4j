package com.webauthn4j.verifier.internal;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.credential.CoreCredentialRecord;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.BadBackupEligibleFlagException;

/**
 * Verifies backup eligibility flag consistency with credential record.
 * <p>
 * Implements WebAuthn Level 3 § 7.2 Step 19 (backup state verification).
 * Ensures that the BE (Backup Eligible) flag in the current authenticator data
 * matches the backup eligibility recorded in the credential record.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2 Verifying an Authentication Assertion</a>
 */
public class BEFlagVerifier {

    private BEFlagVerifier(){}

    public static void verify(Authenticator authenticator, AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if(authenticator instanceof CoreCredentialRecord){
            CoreCredentialRecord coreCredentialRecord = (CoreCredentialRecord) authenticator;
            Boolean backEligibleRecordValue = coreCredentialRecord.isBackupEligible();
            //noinspection StatementWithEmptyBody
            if(backEligibleRecordValue == null){
                //no-op
            }
            else if(backEligibleRecordValue) {
                if(!authenticatorData.isFlagBE()){
                    throw new BadBackupEligibleFlagException("Although credential record BE flag is set, current BE flag is not set");
                }
            }
            else{
                if(authenticatorData.isFlagBE()){
                    throw new BadBackupEligibleFlagException("Although credential record BE flag is not set, current BE flag is set");
                }
            }
        }
    }
}
