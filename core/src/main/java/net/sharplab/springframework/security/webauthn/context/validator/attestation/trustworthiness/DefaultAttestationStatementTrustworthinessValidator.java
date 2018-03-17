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

import net.sharplab.springframework.security.webauthn.anchor.FIDOMetadataServiceTrustAnchorService;
import net.sharplab.springframework.security.webauthn.anchor.WebAuthnTrustAnchorService;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidatorImpl;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath.FIDOMetadataServiceCertPathTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidatorImpl;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidatorImpl;
import org.springframework.util.Assert;

/**
 * Created by ynojima on 2017/09/21.
 */
public class DefaultAttestationStatementTrustworthinessValidator extends AbstractAttestationStatementTrustworthinessValidator {

    private FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService;

    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;
    private ECDAATrustworthinessValidator ecdaaTrustworthinessValidator;
    private CertPathTrustworthinessValidator certPathTrustworthinessValidator;

    public DefaultAttestationStatementTrustworthinessValidator(FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService){
        this.fidoMetadataServiceTrustAnchorService = fidoMetadataServiceTrustAnchorService;
    }

    @Override
    public SelfAttestationTrustworthinessValidator getSelfAttestationTrustworthinessValidator() {
        if(selfAttestationTrustworthinessValidator == null){
            selfAttestationTrustworthinessValidator = new SelfAttestationTrustworthinessValidatorImpl();
        }
        return selfAttestationTrustworthinessValidator;
    }

    public void setSelfAttestationTrustworthinessValidator(SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator) {
        Assert.notNull(fidoMetadataServiceTrustAnchorService, "SelfAttestationTrustworthinessValidator must not be null");
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }

    @Override
    public ECDAATrustworthinessValidator getECDAATrustworthinessValidator() {
        if(ecdaaTrustworthinessValidator == null){
            ecdaaTrustworthinessValidator = new ECDAATrustworthinessValidatorImpl(fidoMetadataServiceTrustAnchorService);
        }
        return ecdaaTrustworthinessValidator;
    }

    public void setECDAATrustworthinessValidator(ECDAATrustworthinessValidator ecdaaTrustworthinessValidator) {
        Assert.notNull(fidoMetadataServiceTrustAnchorService, "ECDAATrustworthinessValidator must not be null");
        this.ecdaaTrustworthinessValidator = ecdaaTrustworthinessValidator;
    }

    @Override
    public CertPathTrustworthinessValidator getCertPathTrustworthinessValidator() {
        if(certPathTrustworthinessValidator == null){
            certPathTrustworthinessValidator = new FIDOMetadataServiceCertPathTrustworthinessValidator(fidoMetadataServiceTrustAnchorService);
        }
        return certPathTrustworthinessValidator;
    }

    public void setCertPathTrustworthinessValidator(CertPathTrustworthinessValidator certPathTrustworthinessValidator) {
        Assert.notNull(fidoMetadataServiceTrustAnchorService, "CertPathTrustworthinessValidator must not be null");
        this.certPathTrustworthinessValidator = certPathTrustworthinessValidator;
    }

    protected FIDOMetadataServiceTrustAnchorService getTrustAnchorService(){
        return fidoMetadataServiceTrustAnchorService;
    }

}
