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

package com.webauthn4j.appattest.validator;

import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.appattest.validator.attestation.statement.appleappattest.AppleAppAttestAttestationStatementValidator;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.CoreRegistrationData;
import com.webauthn4j.data.CoreRegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.validator.CoreRegistrationDataValidator;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.CustomCoreRegistrationValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadAaguidException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.MaliciousCounterValueException;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class DCAttestationDataValidator extends CoreRegistrationDataValidator{

    private static final AAGUID APPLE_APP_ATTEST_ENVIRONMENT_DEVELOPMENT = new AAGUID("appattestdevelop".getBytes());
    private static final AAGUID APPLE_APP_ATTEST_ENVIRONMENT_PRODUCTION = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());

    private boolean production = true;

    public DCAttestationDataValidator(CertPathTrustworthinessValidator certPathTrustworthinessValidator, List<CustomCoreRegistrationValidator> customRegistrationValidatorList, ObjectConverter objectConverter) {
        super(Collections.singletonList(new AppleAppAttestAttestationStatementValidator()),
                certPathTrustworthinessValidator, createSelfAttestationTrustWorthinessValidator(), customRegistrationValidatorList, objectConverter);
    }

    @Override
    public void validate(CoreRegistrationData registrationData, CoreRegistrationParameters registrationParameters) {
        super.validate(registrationData, registrationParameters);
        validateAuthenticatorData(registrationData.getAttestationObject().getAuthenticatorData());
        validateKeyIdentifier(registrationData);
    }

    private void validateKeyIdentifier(CoreRegistrationData registrationData) {
        DCAttestationData dcAttestationData = (DCAttestationData)registrationData;
        byte[] keyIdentifier = dcAttestationData.getKeyIdentifier();
        byte[] credentialId = registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        if (!Arrays.equals(keyIdentifier, credentialId)) {
            throw new BadAttestationStatementException("key identifier doesn't match credentialId.");
        }
    }

    @Override
    protected CoreRegistrationObject createCoreRegistrationObject(CoreRegistrationData registrationData, CoreRegistrationParameters registrationParameters) {
        DCAttestationData dcAttestationData = (DCAttestationData) registrationData;
        return new DCRegistrationObject(
                dcAttestationData.getKeyIdentifier(),
                registrationData.getAttestationObject(),
                registrationData.getAttestationObjectBytes(),
                registrationData.getClientDataHash(),
                registrationParameters.getServerProperty(), Instant.now());
    }

    public boolean isProduction() {
        return production;
    }

    public void setProduction(boolean production) {
        this.production = production;
    }

    private void validateAuthenticatorData(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        if (authenticatorData.getSignCount() != 0) {
            throw new MaliciousCounterValueException("Counter is not zero");
        }

        AAGUID aaguid = authenticatorData.getAttestedCredentialData().getAaguid();
        AAGUID expectedAAGUID = isProduction() ? APPLE_APP_ATTEST_ENVIRONMENT_PRODUCTION : APPLE_APP_ATTEST_ENVIRONMENT_DEVELOPMENT;
        if (!aaguid.equals(expectedAAGUID)) {
            throw new BadAaguidException("Expected AAGUID of either 'appattestdevelop' or 'appattest'");
        }
    }

    private static SelfAttestationTrustworthinessValidator createSelfAttestationTrustWorthinessValidator(){
        DefaultSelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator = new DefaultSelfAttestationTrustworthinessValidator();
        selfAttestationTrustworthinessValidator.setSelfAttestationAllowed(false);
        return selfAttestationTrustworthinessValidator;
    }

}
