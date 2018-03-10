package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;

/**
 * Created by ynojima on 2017/09/21.
 */
public abstract class AbstractAttestationStatementTrustworthinessValidator implements AttestationStatementTrustworthinessValidator {

    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;
    private ECDAATrustworthinessValidator ecdaaTrustworthinessValidator;
    private CertPathTrustworthinessValidator certPathTrustworthinessValidator;

    @Override
    public void validate(WebAuthnAttestationStatement attestationStatement){
        if(attestationStatement.isSelfAttested()){ // self attestation
            if(selfAttestationTrustworthinessValidator == null){
                selfAttestationTrustworthinessValidator = getSelfAttestationTrustworthinessValidator();
            }
            selfAttestationTrustworthinessValidator.validate(attestationStatement);
        }
        else if(isECDAA(attestationStatement)){ //ECDAA
            if (ecdaaTrustworthinessValidator == null){
                ecdaaTrustworthinessValidator = getECDAATrustworthinessValidator();
            }
            ecdaaTrustworthinessValidator.validate(attestationStatement);
        }
        else{
            if(certPathTrustworthinessValidator == null){
                certPathTrustworthinessValidator = getCertPathTrustworthinessValidator();
            }
            certPathTrustworthinessValidator.validate(attestationStatement);
        }
    }

    public abstract SelfAttestationTrustworthinessValidator getSelfAttestationTrustworthinessValidator();

    public abstract ECDAATrustworthinessValidator getECDAATrustworthinessValidator();

    public abstract CertPathTrustworthinessValidator getCertPathTrustworthinessValidator();

    protected boolean isECDAA(WebAuthnAttestationStatement attestationStatement) {
        return false; //TODO: not implemented
    }

}
