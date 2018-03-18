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

package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;

/**
 * Created by ynojima on 2017/09/21.
 */
public abstract class AbstractAttestationStatementTrustworthinessValidator implements AttestationStatementTrustworthinessValidator {

    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;
    private ECDAATrustworthinessValidator ecdaaTrustworthinessValidator;
    private CertPathTrustworthinessValidator certPathTrustworthinessValidator;

    @Override
    public void validate(WebAuthnAttestationStatement attestationStatement) {
        if (attestationStatement.isSelfAttested()) { // self attestation
            if (selfAttestationTrustworthinessValidator == null) {
                selfAttestationTrustworthinessValidator = getSelfAttestationTrustworthinessValidator();
            }
            selfAttestationTrustworthinessValidator.validate(attestationStatement);
        } else if (isECDAA(attestationStatement)) { //ECDAA
            if (ecdaaTrustworthinessValidator == null) {
                ecdaaTrustworthinessValidator = getECDAATrustworthinessValidator();
            }
            ecdaaTrustworthinessValidator.validate(attestationStatement);
        } else {
            if (certPathTrustworthinessValidator == null) {
                certPathTrustworthinessValidator = getCertPathTrustworthinessValidator();
            }
            certPathTrustworthinessValidator.validate(attestationStatement);
        }
    }

    public abstract SelfAttestationTrustworthinessValidator getSelfAttestationTrustworthinessValidator();

    public abstract ECDAATrustworthinessValidator getECDAATrustworthinessValidator();

    public abstract CertPathTrustworthinessValidator getCertPathTrustworthinessValidator();

    protected boolean isECDAA(WebAuthnAttestationStatement attestationStatement) {
        return false; //TODO: not implemented
    }

}
