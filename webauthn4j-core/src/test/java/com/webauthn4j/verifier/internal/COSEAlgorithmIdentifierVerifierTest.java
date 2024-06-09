package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.verifier.exception.NotAllowedAlgorithmException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

class COSEAlgorithmIdentifierVerifierTest {

    @Test
    void verify_test(){
        List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256), new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));
        COSEAlgorithmIdentifierVerifier.verify(COSEAlgorithmIdentifier.ES256, pubKeyCredParams);
    }

    @Test
    void verify_not_allowed_alg_test(){
        List<PublicKeyCredentialParameters> pubKeyCredParams = Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));
        assertThrows(NotAllowedAlgorithmException.class,
                () -> COSEAlgorithmIdentifierVerifier.verify(COSEAlgorithmIdentifier.ES256, pubKeyCredParams)
        );
    }


}