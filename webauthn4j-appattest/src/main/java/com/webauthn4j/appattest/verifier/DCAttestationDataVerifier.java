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

package com.webauthn4j.appattest.verifier;

import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.appattest.verifier.attestation.statement.appleappattest.AppleAppAttestAttestationStatementVerifier;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.CoreRegistrationData;
import com.webauthn4j.data.CoreRegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.CoreRegistrationDataVerifier;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.CustomCoreRegistrationVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.BadAaguidException;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class DCAttestationDataVerifier extends CoreRegistrationDataVerifier {

    private static final AAGUID APPLE_APP_ATTEST_ENVIRONMENT_DEVELOPMENT = new AAGUID("appattestdevelop".getBytes());
    private static final AAGUID APPLE_APP_ATTEST_ENVIRONMENT_PRODUCTION = new AAGUID("appattest\0\0\0\0\0\0\0".getBytes());

    private boolean production = true;

    public DCAttestationDataVerifier(@NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier, @NotNull List<CustomCoreRegistrationVerifier> customRegistrationValidatorList, @NotNull ObjectConverter objectConverter) {
        super(Collections.singletonList(new AppleAppAttestAttestationStatementVerifier()),
                certPathTrustworthinessVerifier, createSelfAttestationTrustWorthinessValidator(), customRegistrationValidatorList, objectConverter);
    }

    private static @NotNull SelfAttestationTrustworthinessVerifier createSelfAttestationTrustWorthinessValidator() {
        return new DefaultSelfAttestationTrustworthinessVerifier(false);
    }

    @Override
    public void verify(@NotNull CoreRegistrationData registrationData, @NotNull CoreRegistrationParameters registrationParameters) {
        super.verify(registrationData, registrationParameters);
        //noinspection ConstantConditions as null check is already done in super class
        validateAuthenticatorData(registrationData.getAttestationObject().getAuthenticatorData());
        validateKeyId(registrationData);
    }

    private void validateKeyId(@NotNull CoreRegistrationData registrationData) {
        DCAttestationData dcAttestationData = (DCAttestationData) registrationData;
        byte[] keyId = dcAttestationData.getKeyId();
        //noinspection ConstantConditions as null check is already done in caller
        byte[] credentialId = registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        // As keyId is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(keyId, credentialId)) {
            throw new BadAttestationStatementException("key identifier doesn't match credentialId.");
        }
    }

    @Override
    protected @NotNull CoreRegistrationObject createCoreRegistrationObject(@NotNull CoreRegistrationData registrationData, @NotNull CoreRegistrationParameters registrationParameters) {

        AssertUtil.notNull(registrationData, "registrationData must not be null");
        AssertUtil.notNull(registrationParameters, "registrationParameters must not be null");

        DCAttestationData dcAttestationData = (DCAttestationData) registrationData;
        //noinspection ConstantConditions null check is already done in caller
        return new DCRegistrationObject(
                dcAttestationData.getKeyId(),
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

    private void validateAuthenticatorData(@NotNull AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        if (authenticatorData.getSignCount() != 0) {
            throw new MaliciousCounterValueException("Counter is not zero");
        }

        //noinspection ConstantConditions as null check is already done in caller
        AAGUID aaguid = authenticatorData.getAttestedCredentialData().getAaguid();
        AAGUID expectedAAGUID = isProduction() ? APPLE_APP_ATTEST_ENVIRONMENT_PRODUCTION : APPLE_APP_ATTEST_ENVIRONMENT_DEVELOPMENT;
        if (!aaguid.equals(expectedAAGUID)) {
            throw new BadAaguidException("Expected AAGUID of either 'appattestdevelop' or 'appattest'");
        }
    }

}
