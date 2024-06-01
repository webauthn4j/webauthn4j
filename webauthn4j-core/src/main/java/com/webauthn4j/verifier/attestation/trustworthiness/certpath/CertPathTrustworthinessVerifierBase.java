/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.verifier.exception.CertificateException;
import com.webauthn4j.verifier.exception.TrustAnchorNotFoundException;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

public abstract class CertPathTrustworthinessVerifierBase implements CertPathTrustworthinessVerifier {

    private boolean fullChainProhibited = false;
    private boolean revocationCheckEnabled = false;
    private boolean policyQualifiersRejected = false;

    public void verify(@NotNull AAGUID aaguid, @NotNull CertificateBaseAttestationStatement attestationStatement, @NotNull Instant timestamp) {
        AssertUtil.notNull(aaguid, "aaguid must not be null");
        AssertUtil.notNull(aaguid, "attestationStatement must not be null");
        AssertUtil.notNull(aaguid, "timestamp must not be null");

        //noinspection ConstantConditions as null check is already done in caller
        CertPath certPath = attestationStatement.getX5c().createCertPath();

        Set<TrustAnchor> trustAnchors = resolveTrustAnchors(aaguid);

        if (trustAnchors.isEmpty()) {
            throw new TrustAnchorNotFoundException("TrustAnchors are not found for AAGUID: " + aaguid.toString());
        }

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        certPathParameters.setPolicyQualifiersRejected(policyQualifiersRejected);

        certPathParameters.setRevocationEnabled(revocationCheckEnabled);
        certPathParameters.setDate(Date.from(timestamp));

        PKIXCertPathValidatorResult result;
        try {
            result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new com.webauthn4j.verifier.exception.CertificateException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new com.webauthn4j.verifier.exception.CertificateException("invalid cert path", e);
        }
        if (fullChainProhibited && certPath.getCertificates().contains(result.getTrustAnchor().getTrustedCert())) {
            throw new CertificateException("`certpath` must not contain full chain.");
        }
    }

    protected abstract @NotNull Set<TrustAnchor> resolveTrustAnchors(@NotNull AAGUID aaguid);


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
