/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.exception.CertificateException;
import net.sharplab.springframework.security.webauthn.exception.SelfAttestationProhibitedException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Validates {@link WebAuthnAttestationStatement} as self attestation
 */
public class SelfAttestationTrustworthinessValidatorImpl implements SelfAttestationTrustworthinessValidator {

    //~ Instance fields ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private boolean isSelfAttestationAllowed = true;

    public void validate(WebAuthnAttestationStatement attestationStatement){
        if(!attestationStatement.isSelfAttested()){
            throw new IllegalArgumentException(messages.getMessage("SelfAttestationTrustworthinessValidatorImpl.attestationStatementIsNotSelfAttested",
                    "attestationStatement is not self attested"));
        }
        if(isSelfAttestationAllowed()){
            X509Certificate attestationCertificate = attestationStatement.getEndEntityCertificate();
            try {
                attestationCertificate.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new CertificateException(messages.getMessage("SelfAttestationTrustworthinessValidatorImpl.certificateExpired",
                        "Certificate expired"), e);
            } catch (CertificateNotYetValidException e) {
                throw new CertificateException(messages.getMessage("SelfAttestationTrustworthinessValidatorImpl.certificateNotYetValid",
                        "Certificate not yet valid"), e);
            }
        }
        else {
            throw new SelfAttestationProhibitedException(
                    messages.getMessage("SelfAttestationTrustworthinessValidatorImpl.selfAttestationProhibited",
                            "Self attestations is prohibited"));
        }
    }

    public boolean isSelfAttestationAllowed() {
        return this.isSelfAttestationAllowed;
    }

    public void setSelfAttestationAllowed(boolean selfAttestationAllowed) {
        this.isSelfAttestationAllowed = selfAttestationAllowed;
    }
}
