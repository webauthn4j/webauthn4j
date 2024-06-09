package com.webauthn4j.verifier.internal;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.credential.CoreCredentialRecord;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.BadBackupEligibleFlagException;

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
