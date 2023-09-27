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

package com.webauthn4j.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.validator.exception.CertificateException;
import com.webauthn4j.validator.exception.TrustAnchorNotFoundException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

public class DefaultCertPathTrustworthinessValidator implements CertPathTrustworthinessValidator{

    private final TrustAnchorRepository trustAnchorRepository;

    private boolean fullChainProhibited = false;
    private boolean revocationCheckEnabled = false;
    private boolean policyQualifiersRejected = false;

    public DefaultCertPathTrustworthinessValidator(TrustAnchorRepository trustAnchorRepository) {
        this.trustAnchorRepository = trustAnchorRepository;
    }

    @Override
    public void validate(@NonNull AAGUID aaguid, @NonNull CertificateBaseAttestationStatement attestationStatement, @NonNull Instant timestamp) {
        AssertUtil.notNull(aaguid, "aaguid must not be null");
        AssertUtil.notNull(aaguid, "attestationStatement must not be null");
        AssertUtil.notNull(aaguid, "timestamp must not be null");

        //noinspection ConstantConditions as null check is already done in caller
        CertPath certPath = attestationStatement.getX5c().createCertPath();

        Set<TrustAnchor> trustAnchors;

        if(attestationStatement instanceof FIDOU2FAttestationStatement){
            FIDOU2FAttestationStatement fidou2fAttestationStatement = (FIDOU2FAttestationStatement) attestationStatement;
            byte[] subjectKeyIdentifier = CertificateUtil.extractSubjectKeyIdentifier(fidou2fAttestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate());
            trustAnchors = trustAnchorRepository.find(subjectKeyIdentifier);
        }
        else {
            trustAnchors = trustAnchorRepository.find(aaguid);
        }

        validateCertPath(certPath, trustAnchors, timestamp);
    }

    private TrustAnchor validateCertPath(CertPath certPath, Set<TrustAnchor> trustAnchors, Instant timestamp){

        if (trustAnchors.isEmpty()) {
            throw new TrustAnchorNotFoundException("TrustAnchors are not found");
        }

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        certPathParameters.setPolicyQualifiersRejected(policyQualifiersRejected);

        certPathParameters.setRevocationEnabled(revocationCheckEnabled);
        certPathParameters.setDate(Date.from(timestamp));

        TrustAnchor trustAnchor;

        // if itself is an acceptable certificate, it is valid cert path
        if(certPath.getCertificates().size() == 1){
            Certificate certificate = certPath.getCertificates().get(0);
            trustAnchor = trustAnchors.stream().filter(it -> it.getTrustedCert().equals(certificate)).findFirst().orElse(null);
            if(trustAnchor != null){
                return trustAnchor;
            }
        }

        // or validate the certificate chain path
        PKIXCertPathValidatorResult result;
        try {
            result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new com.webauthn4j.validator.exception.CertificateException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new com.webauthn4j.validator.exception.CertificateException("invalid cert path", e);
        }
        if (fullChainProhibited && certPath.getCertificates().contains(result.getTrustAnchor().getTrustedCert())) {
            throw new CertificateException("`certpath` must not contain full chain.");
        }
        return trustAnchors.stream()
                .filter(item -> Objects.equals(item, result.getTrustAnchor()))
                .findFirst().orElseThrow(()-> new IllegalStateException("Matching TrustAnchor is not found."));
    }

    public boolean isFullChainProhibited() {
        return fullChainProhibited;
    }

    public void setFullChainProhibited(boolean fullChainProhibited) {
        this.fullChainProhibited = fullChainProhibited;
    }

    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }

    public void setRevocationCheckEnabled(boolean revocationCheckEnabled) {
        this.revocationCheckEnabled = revocationCheckEnabled;
    }

    public boolean isPolicyQualifiersRejected() {
        return policyQualifiersRejected;
    }

    public void setPolicyQualifiersRejected(boolean policyQualifiersRejected) {
        this.policyQualifiersRejected = policyQualifiersRejected;
    }
}
