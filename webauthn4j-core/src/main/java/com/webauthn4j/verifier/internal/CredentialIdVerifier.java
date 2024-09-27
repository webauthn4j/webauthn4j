package com.webauthn4j.verifier.internal;

import com.webauthn4j.verifier.exception.NotAllowedCredentialIdException;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.List;

public class CredentialIdVerifier {

    private CredentialIdVerifier(){}

    public static void verify(byte[] credentialId, @Nullable List<byte[]> allowCredentials) {
        // As allowCredentials are known data to client side(potential attacker),
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if(allowCredentials != null && allowCredentials.stream().noneMatch(item -> Arrays.equals(item, credentialId))){
            throw new NotAllowedCredentialIdException("credentialId not listed in allowCredentials is used.");
        }
    }
}
