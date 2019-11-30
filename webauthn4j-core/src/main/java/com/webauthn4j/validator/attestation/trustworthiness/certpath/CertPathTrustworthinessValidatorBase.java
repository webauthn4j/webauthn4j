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

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.validator.exception.CertificateException;
import com.webauthn4j.validator.exception.TrustAnchorNotFoundException;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.Set;

public abstract class CertPathTrustworthinessValidatorBase implements CertPathTrustworthinessValidator {

    private boolean fullChainProhibited = false;

    public void validate(AAGUID aaguid, CertificateBaseAttestationStatement attestationStatement) {
        CertPath certPath = attestationStatement.getX5c().createCertPath();

        Set<TrustAnchor> trustAnchors = resolveTrustAnchors(aaguid);

        if (trustAnchors.isEmpty()) {
            throw new TrustAnchorNotFoundException("TrustAnchors are not found for AAGUID: " + aaguid.toString());
        }

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        certPathParameters.setPolicyQualifiersRejected(false); // As policy qualifiers are checked manually in attestation statement validator, it is turned off

        certPathParameters.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result;
        try {
            result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            //TODO add registrationObject
            throw new com.webauthn4j.validator.exception.CertificateException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            //TODO add registrationObject
            throw new com.webauthn4j.validator.exception.CertificateException("invalid cert path", e);
        }
        if (fullChainProhibited && certPath.getCertificates().contains(result.getTrustAnchor().getTrustedCert())) {
            //TODO add registrationObject
            throw new CertificateException("`certpath` must not contain full chain.");
        }
    }

    protected abstract Set<TrustAnchor> resolveTrustAnchors(AAGUID aaguid);


    public boolean isFullChainProhibited() {
        return fullChainProhibited;
    }

    public void setFullChainProhibited(boolean fullChainProhibited) {
        this.fullChainProhibited = fullChainProhibited;
    }

}
