package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.verifier.exception.NotAllowedAlgorithmException;

import java.util.List;

public class COSEAlgorithmIdentifierVerifier {

    private COSEAlgorithmIdentifierVerifier(){}

    public static void verify(COSEAlgorithmIdentifier alg, List<PublicKeyCredentialParameters> pubKeyCredParams) {
        if(pubKeyCredParams != null && pubKeyCredParams.stream().noneMatch(item -> item.getAlg().equals(alg))){
            throw new NotAllowedAlgorithmException("alg not listed in options.pubKeyCredParams is used.");
        }
    }
}
