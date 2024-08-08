package com.webauthn4j.verifier.internal;

import com.webauthn4j.verifier.exception.CredentialIdTooLongException;

public class CredentialIdLengthVerifier {

    private CredentialIdLengthVerifier(){}

    public static void verify(byte[] credentialId, int maxCredentialIdLength) {
        if(maxCredentialIdLength >= 0 && credentialId.length > maxCredentialIdLength){
            throw new CredentialIdTooLongException(String.format("credentialId exceeds maxCredentialIdSize(%d bytes)", maxCredentialIdLength));
        }
    }
}
