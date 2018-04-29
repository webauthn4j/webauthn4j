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

package com.webauthn4j.validator.attestation.trustworthiness.basic;

import com.webauthn4j.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.validator.exception.CertificateException;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * UntrustedCATolerantTrustworthinessValidator
 */
public class UntrustedCATolerantTrustworthinessValidator implements BasicTrustworthinessValidator {

    //~ Instance fields ================================================================================================

    private boolean softFail = false;

    @Override
    public void validate(WebAuthnAttestationStatement attestationStatement) {
        X509Certificate attestationCertificate = attestationStatement.getEndEntityCertificate();
        try {
            attestationCertificate.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CertificateException("Certificate expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new CertificateException("Certificate is not yet valid", e);
        }
    }
}
