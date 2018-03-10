package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness;

import net.sharplab.springframework.security.webauthn.anchor.FIDOMetadataServiceTrustAnchorService;
import net.sharplab.springframework.security.webauthn.anchor.WebAuthnTrustAnchorService;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.UntrustedCATolerantTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidatorImpl;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidatorImpl;

/**
 * Created by ynojima on 2017/09/21.
 */
public class LooseAttestationStatementTrustworthinessValidator extends AbstractAttestationStatementTrustworthinessValidator {

    private FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService;

    public LooseAttestationStatementTrustworthinessValidator(FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService){
        super();
        this.fidoMetadataServiceTrustAnchorService = fidoMetadataServiceTrustAnchorService;
    }

    @Override
    public SelfAttestationTrustworthinessValidator getSelfAttestationTrustworthinessValidator() {
        SelfAttestationTrustworthinessValidatorImpl selfAttestationTrustworthinessValidator = new SelfAttestationTrustworthinessValidatorImpl();
        selfAttestationTrustworthinessValidator.setSelfAttestationAllowed(true);
        return selfAttestationTrustworthinessValidator;
    }

    @Override
    public ECDAATrustworthinessValidator getECDAATrustworthinessValidator() {
        return new ECDAATrustworthinessValidatorImpl(fidoMetadataServiceTrustAnchorService);
    }

    @Override
    public CertPathTrustworthinessValidator getCertPathTrustworthinessValidator() {
        UntrustedCATolerantTrustworthinessValidator certPathTrustworthinessValidator = new UntrustedCATolerantTrustworthinessValidator();
        return certPathTrustworthinessValidator;
    }
}
