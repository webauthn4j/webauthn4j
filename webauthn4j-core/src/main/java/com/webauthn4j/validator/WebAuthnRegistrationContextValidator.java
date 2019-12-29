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


import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.NullECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Validates the specified {@link com.webauthn4j.data.WebAuthnRegistrationContext} instance
 * @deprecated {@link WebAuthnRegistrationContextValidator} is deprecated. please use {@link WebAuthnManager} instead.
 */
@Deprecated
public class WebAuthnRegistrationContextValidator {

    // ~ Instance fields
    // ================================================================================================

    private final List<CustomRegistrationValidator> customRegistrationValidators = new ArrayList<>();

    private final WebAuthnManager webAuthnManager;

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator
    ) {
        this(attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                new DefaultSelfAttestationTrustworthinessValidator(),
                new JsonConverter(),
                new CborConverter());
    }

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
            SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator
    ) {
        this(attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                new JsonConverter(),
                new CborConverter());
    }

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
            JsonConverter jsonConverter,
            CborConverter cborConverter
    ) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                new DefaultSelfAttestationTrustworthinessValidator(),
                jsonConverter,
                cborConverter
        );
    }

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
            SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
            JsonConverter jsonConverter,
            CborConverter cborConverter
    ) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(ecdaaTrustworthinessValidator, "ecdaaTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");
        AssertUtil.notNull(jsonConverter, "jsonConverter must not be null");
        AssertUtil.notNull(cborConverter, "cborConverter must not be null");

        this.webAuthnManager = new WebAuthnManager(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                Collections.emptyList(),
                new ObjectConverter(jsonConverter, cborConverter));
    }


    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnRegistrationContextValidator} with non strict configuration
     *
     * @return configured {@link WebAuthnRegistrationContextValidator}
     */
    public static WebAuthnRegistrationContextValidator createNonStrictRegistrationContextValidator() {
        return createNonStrictRegistrationContextValidator(new JsonConverter(), new CborConverter());
    }

    /**
     * Creates {@link WebAuthnRegistrationContextValidator} with non strict configuration
     *
     * @param jsonConverter json converter
     * @param cborConverter cobr converter
     * @return configured {@link WebAuthnRegistrationContextValidator}
     */
    public static WebAuthnRegistrationContextValidator createNonStrictRegistrationContextValidator(JsonConverter jsonConverter, CborConverter cborConverter) {
        return new WebAuthnRegistrationContextValidator(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new NullFIDOU2FAttestationStatementValidator(),
                        new NullPackedAttestationStatementValidator(),
                        new NullTPMAttestationStatementValidator(),
                        new NullAndroidKeyAttestationStatementValidator(),
                        new NullAndroidSafetyNetAttestationStatementValidator()
                ),
                new NullCertPathTrustworthinessValidator(),
                new NullECDAATrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                jsonConverter,
                cborConverter
        );
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * validates WebAuthn registration request
     *
     * @param webAuthnRegistrationContext registration context
     * @return validation result
     * @throws DataConversionException if the input cannot be parsed
     * @throws ValidationException     if the input is not valid from the point of WebAuthn validation steps
     * @throws WebAuthnException       if WebAuthn error occurred
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    public WebAuthnRegistrationContextValidationResponse validate(com.webauthn4j.data.WebAuthnRegistrationContext webAuthnRegistrationContext) throws WebAuthnException {

        RegistrationRequest registrationRequest = new RegistrationRequest(
                webAuthnRegistrationContext.getAttestationObject(),
                webAuthnRegistrationContext.getClientDataJSON(),
                webAuthnRegistrationContext.getClientExtensionsJSON(),
                webAuthnRegistrationContext.getTransports()
        );
        RegistrationParameters registrationParameters = new RegistrationParameters(
                webAuthnRegistrationContext.getServerProperty(),
                webAuthnRegistrationContext.isUserVerificationRequired(),
                webAuthnRegistrationContext.isUserPresenceRequired(),
                webAuthnRegistrationContext.getExpectedExtensionIds()

        );

        RegistrationData registrationData = webAuthnManager.validate(registrationRequest, registrationParameters);

        return new WebAuthnRegistrationContextValidationResponse(
                registrationData.getCollectedClientData(),
                registrationData.getAttestationObject(),
                registrationData.getClientExtensions());
    }

    public List<CustomRegistrationValidator> getCustomRegistrationValidators() {
        return customRegistrationValidators;
    }

}
