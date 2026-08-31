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

package com.webauthn4j.metadata.util.internal;

import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.CertPathChecker;
import com.webauthn4j.metadata.exception.CertPathCheckException;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.util.CertificateUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.util.EnumSet;

public class DefaultCertPathChecker implements CertPathChecker {

    @Override
    public void check(CertPathCheckContext context) throws MDSException {
        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(context.getTrustAnchors());
        certPathParameters.setRevocationEnabled(context.isRevocationCheckEnabled());
        if(context.isRevocationCheckEnabled()){
            PKIXRevocationChecker pkixRevocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
            pkixRevocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS));
            certPathParameters.addCertPathChecker(pkixRevocationChecker);
        }
        try {
            certPathValidator.validate(context.getCertPath(), certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertPathCheckException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new CertPathCheckException("invalid cert path", e);
        }
    }
}
