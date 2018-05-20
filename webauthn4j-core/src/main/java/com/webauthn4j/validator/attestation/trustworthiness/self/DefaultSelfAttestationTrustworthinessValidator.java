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

package com.webauthn4j.validator.attestation.trustworthiness.self;

import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.validator.exception.CertificateException;
import com.webauthn4j.validator.exception.SelfAttestationProhibitedException;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Validates {@link AttestationStatement} as self attestation
 */
public class DefaultSelfAttestationTrustworthinessValidator implements SelfAttestationTrustworthinessValidator {

    //~ Instance fields ================================================================================================
    private boolean isSelfAttestationAllowed = true;

    public void validate(CertificateBaseAttestationStatement attestationStatement) {
        if (isSelfAttestationAllowed()) {
            X509Certificate attestationCertificate = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate();
            try {
                attestationCertificate.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new CertificateException("Certificate expired", e);
            } catch (CertificateNotYetValidException e) {
                throw new CertificateException("Certificate not yet valid", e);
            }
        } else {
            throw new SelfAttestationProhibitedException("SELF attestations is prohibited by configuration");
        }
    }

    @SuppressWarnings("WeakerAccess")
    public boolean isSelfAttestationAllowed() {
        return this.isSelfAttestationAllowed;
    }

    public void setSelfAttestationAllowed(boolean selfAttestationAllowed) {
        this.isSelfAttestationAllowed = selfAttestationAllowed;
    }
}
