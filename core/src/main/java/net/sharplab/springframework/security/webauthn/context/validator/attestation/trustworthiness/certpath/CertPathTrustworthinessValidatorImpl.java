package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath;

import net.sharplab.springframework.security.webauthn.anchor.WebAuthnTrustAnchorService;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.EnumSet;
import java.util.Set;

/**
 * Created by ynojima on 2017/09/21.
 */
public class CertPathTrustworthinessValidatorImpl implements CertPathTrustworthinessValidator {

    private WebAuthnTrustAnchorService webAuthnTrustAnchorService;

    private boolean isRevocationCheckEnabled = false;

    public CertPathTrustworthinessValidatorImpl(WebAuthnTrustAnchorService webAuthnTrustAnchorService){
        this.webAuthnTrustAnchorService = webAuthnTrustAnchorService;
    }

    public void validate(WebAuthnAttestationStatement attestationStatement){

        FIDOU2FAttestationStatement fidoU2FAttestationStatement = (FIDOU2FAttestationStatement) attestationStatement;
        CertPath certPath = fidoU2FAttestationStatement.getX5c();
        Set<TrustAnchor> trustAnchors = webAuthnTrustAnchorService.getTrustAnchors();

        CertPathValidator certPathValidator = CertificateUtil.generateCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.generatePKIXParameters(trustAnchors);

        if(isRevocationCheckEnabled()){
            //Set PKIXRevocationChecker to enable CRL based revocation check, which is disabled by default.
            //Ref. http://docs.oracle.com/javase/7/docs/technotes/guides/security/certpath/CertPathProgGuide.html#AppB
            PKIXRevocationChecker pkixRevocationChecker = (PKIXRevocationChecker)certPathValidator.getRevocationChecker();
            pkixRevocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS));
            certPathParameters.addCertPathChecker(pkixRevocationChecker);
        }
        else {
            certPathParameters.setRevocationEnabled(false);
        }

        try {
            certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        } catch (CertPathValidatorException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }

    public boolean isRevocationCheckEnabled() {
        return isRevocationCheckEnabled;
    }

    public void setRevocationCheckEnabled(boolean revocationCheckEnabled) {
        isRevocationCheckEnabled = revocationCheckEnabled;
    }
}
