package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Created by ynojima on 2017/09/21.
 */
public class UntrustedCATolerantTrustworthinessValidator implements CertPathTrustworthinessValidator {

    //~ Instance fields ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private boolean softFail = false;

    @Override
    public void validate(WebAuthnAttestationStatement attestationStatement) {
        X509Certificate attestationCertificate = attestationStatement.getEndEntityCertificate();
        if(attestationCertificate == null){
            return;
        }
        try {
            attestationCertificate.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new net.sharplab.springframework.security.webauthn.exception.CertificateException(messages.getMessage("SelfAttestationTrustworthinessValidatorImpl.certificateExpired",
                    "Certificate expired"), e);
        } catch (CertificateNotYetValidException e) {
            throw new net.sharplab.springframework.security.webauthn.exception.CertificateException(messages.getMessage("SelfAttestationTrustworthinessValidatorImpl.certificateNotYetValid",
                    "Certificate not yet valid"), e);
        }
    }
}
