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

package com.webauthn4j.async.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.CertificateException;
import com.webauthn4j.verifier.exception.TrustAnchorNotFoundException;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class DefaultCertPathTrustworthinessAsyncVerifier implements CertPathTrustworthinessAsyncVerifier {

    private final TrustAnchorAsyncRepository trustAnchorAsyncRepository;

    private boolean fullChainProhibited = false;
    private boolean policyQualifiersRejected = false;

    public DefaultCertPathTrustworthinessAsyncVerifier(TrustAnchorAsyncRepository trustAnchorAsyncRepository) {
        this.trustAnchorAsyncRepository = trustAnchorAsyncRepository;
    }

    @Override
    public CompletionStage<Void> verify(@NotNull AAGUID aaguid, @NotNull CertificateBaseAttestationStatement attestationStatement, @NotNull Instant timestamp) {
        return CompletionStageUtil.compose(()->{
            AssertUtil.notNull(aaguid, "aaguid must not be null");
            AssertUtil.notNull(attestationStatement, "attestationStatement must not be null");
            AssertUtil.notNull(timestamp, "timestamp must not be null");

            if(attestationStatement instanceof FIDOU2FAttestationStatement){
                FIDOU2FAttestationStatement fidou2fAttestationStatement = (FIDOU2FAttestationStatement) attestationStatement;
                byte[] subjectKeyIdentifier = DefaultCertPathTrustworthinessVerifier.extractSubjectKeyIdentifier(fidou2fAttestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate());
                return trustAnchorAsyncRepository.find(subjectKeyIdentifier);
            }
            else {
                return trustAnchorAsyncRepository.find(aaguid);
            }
        }).thenCompose(trustAnchors -> {
            //noinspection ConstantConditions as null check is already done in caller
            CertPath certPath = attestationStatement.getX5c().createCertPath();
            verifyCertPath(certPath, trustAnchors, timestamp);
            return CompletableFuture.completedFuture(null);
        });
    }

    private TrustAnchor verifyCertPath(CertPath certPath, Set<TrustAnchor> trustAnchors, Instant timestamp){

        if (trustAnchors.isEmpty()) {
            throw new TrustAnchorNotFoundException("TrustAnchors are not found");
        }

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);

        certPathParameters.setPolicyQualifiersRejected(this.policyQualifiersRejected);
        // revocationCheckEnabled flag is intentionally removed from DefaultCerPathTrustworthinessAsyncVerifier
        // because RevocationChecker fetches CRL with URLConnection in URICertStore, which is blocking API.
        certPathParameters.setRevocationEnabled(false);

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

        // or verify the certificate chain path
        PKIXCertPathValidatorResult result;
        try {
            result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new CertificateException("invalid cert path", e);
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

    public boolean isPolicyQualifiersRejected() {
        return this.policyQualifiersRejected;
    }

    public void setPolicyQualifiersRejected(boolean policyQualifiersRejected) {
        this.policyQualifiersRejected = policyQualifiersRejected;
    }


}
