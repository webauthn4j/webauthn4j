package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa;

import net.sharplab.springframework.security.webauthn.anchor.FIDOMetadataServiceTrustAnchorService;
import net.sharplab.springframework.security.webauthn.anchor.WebAuthnTrustAnchorService;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;

/**
 * Created by ynojima on 2017/09/21.
 */
public class ECDAATrustworthinessValidatorImpl implements ECDAATrustworthinessValidator {

    private FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService;

    public ECDAATrustworthinessValidatorImpl(FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService){
        this.fidoMetadataServiceTrustAnchorService = fidoMetadataServiceTrustAnchorService;
    }

    public void validate(WebAuthnAttestationStatement attestationStatement){
        throw new IllegalStateException("not implemented");
    }
}
