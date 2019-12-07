/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.validator;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnAuthenticationData;
import com.webauthn4j.data.WebAuthnAuthenticationParameters;
import com.webauthn4j.data.WebAuthnAuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.NullECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import com.webauthn4j.validator.exception.ValidationException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Validates the specified {@link WebAuthnAuthenticationContext} instance
 * @deprecated {@link WebAuthnAuthenticationContextValidator} is deprecated. please use {@link WebAuthnManager} instead.
 */
@Deprecated
public class WebAuthnAuthenticationContextValidator {

    //~ Instance fields
    // ================================================================================================

    private final WebAuthnManager webAuthnManager;
    private List<CustomAuthenticationValidator> customAuthenticationValidators = new ArrayList<>();

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnAuthenticationContextValidator() {
        this(new JsonConverter(), new CborConverter());
    }

    public WebAuthnAuthenticationContextValidator(JsonConverter jsonConverter, CborConverter cborConverter) {
        AssertUtil.notNull(jsonConverter, "jsonConverter must not be null");
        AssertUtil.notNull(cborConverter, "cborConverter must not be null");

        webAuthnManager = new WebAuthnManager(
                Collections.emptyList(),
                new NullCertPathTrustworthinessValidator(),
                new NullECDAATrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                Collections.emptyList(),
                customAuthenticationValidators,
                jsonConverter,
                cborConverter
        );
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * validates WebAuthn authentication request
     *
     * @param authenticationContext authentication context
     * @param authenticator         authenticator to be checked against
     * @return validation result
     * @throws DataConversionException if the input cannot be parsed
     * @throws ValidationException     if the input is not valid from the point of WebAuthn validation steps
     * @throws WebAuthnException       if WebAuthn error occurred
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    public WebAuthnAuthenticationContextValidationResponse validate(WebAuthnAuthenticationContext authenticationContext, Authenticator authenticator) throws WebAuthnException {

        WebAuthnAuthenticationRequest webAuthnAuthenticationRequest = new WebAuthnAuthenticationRequest(
                authenticationContext.getCredentialId(),
                authenticationContext.getUserHandle(),
                authenticationContext.getAuthenticatorData(),
                authenticationContext.getClientDataJSON(),
                authenticationContext.getClientExtensionsJSON(),
                authenticationContext.getSignature()
        );
        WebAuthnAuthenticationParameters webAuthnAuthenticationParameters = new WebAuthnAuthenticationParameters(
                authenticationContext.getServerProperty(),
                authenticator,
                LocalDateTime.now(),
                authenticationContext.isUserVerificationRequired(),
                authenticationContext.isUserPresenceRequired()  ,
                authenticationContext.getExpectedExtensionIds()
        );
        WebAuthnAuthenticationData webAuthnAuthenticationData = webAuthnManager.parseAuthenticationRequest(webAuthnAuthenticationRequest);
        webAuthnAuthenticationData.validate(webAuthnAuthenticationParameters);

        return new WebAuthnAuthenticationContextValidationResponse(
                webAuthnAuthenticationData.getCollectedClientData(),
                webAuthnAuthenticationData.getAuthenticatorData(),
                webAuthnAuthenticationData.getClientExtensions());
    }

    void validateAuthenticatorData(AuthenticatorData authenticatorData) {
        if (authenticatorData.getAttestedCredentialData() != null) {
            throw new ConstraintViolationException("attestedCredentialData must be null on authentication");
        }
    }

    public MaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return webAuthnManager.getWebAuthnAuthenticationDataValidator().getMaliciousCounterValueHandler();
    }

    public void setMaliciousCounterValueHandler(MaliciousCounterValueHandler maliciousCounterValueHandler) {
        AssertUtil.notNull(maliciousCounterValueHandler, "maliciousCounterValueHandler must not be null");
        webAuthnManager.getWebAuthnAuthenticationDataValidator().setMaliciousCounterValueHandler(maliciousCounterValueHandler);
    }

    public List<CustomAuthenticationValidator> getCustomAuthenticationValidators() {
        return customAuthenticationValidators;
    }
}
