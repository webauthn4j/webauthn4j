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

package com.webauthn4j.validator;


import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
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
import com.webauthn4j.validator.exception.*;

import java.util.*;

/**
 * Validates the specified {@link WebAuthnRegistrationContext} instance
 */
public class WebAuthnRegistrationContextValidator {

    // ~ Instance fields
    // ================================================================================================

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final ChallengeValidator challengeValidator = new ChallengeValidator();
    private final OriginValidator originValidator = new OriginValidator();
    private final TokenBindingValidator tokenBindingValidator = new TokenBindingValidator();
    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private final ExtensionValidator extensionValidator = new ExtensionValidator();
    private final List<CustomRegistrationValidator> customRegistrationValidators = new ArrayList<>();

    private final AttestationValidator attestationValidator;


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


        collectedClientDataConverter = new CollectedClientDataConverter(jsonConverter);
        attestationObjectConverter = new AttestationObjectConverter(cborConverter);
        authenticatorTransportConverter = new AuthenticatorTransportConverter();
        authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(jsonConverter);

        this.attestationValidator = new AttestationValidator(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator);
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
     * @param registrationContext registration context
     * @return validation result
     * @throws DataConversionException if the input cannot be parsed
     * @throws ValidationException     if the input is not valid from the point of WebAuthn validation steps
     * @throws WebAuthnException       if WebAuthn error occurred
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    public WebAuthnRegistrationContextValidationResponse validate(WebAuthnRegistrationContext registrationContext) throws WebAuthnException {

        BeanAssertUtil.validate(registrationContext);

        byte[] clientDataBytes = registrationContext.getClientDataJSON();
        byte[] attestationObjectBytes = registrationContext.getAttestationObject();

        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        Set<AuthenticatorTransport> transports = authenticatorTransportConverter.convertSet(registrationContext.getTransports());
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(registrationContext.getClientExtensionsJSON());

        BeanAssertUtil.validate(collectedClientData);
        BeanAssertUtil.validate(attestationObject);
        BeanAssertUtil.validateAuthenticationExtensionsClientOutputs(clientExtensions);

        validateAuthenticatorDataField(attestationObject.getAuthenticatorData());

        byte[] authenticatorDataBytes = attestationObjectConverter.extractAuthenticatorData(attestationObjectBytes);

        RegistrationObject registrationObject = new RegistrationObject(
                collectedClientData,
                clientDataBytes,
                attestationObject,
                attestationObjectBytes,
                authenticatorDataBytes,
                transports,
                clientExtensions,
                registrationContext.getServerProperty()
        );

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
        ServerProperty serverProperty = registrationContext.getServerProperty();

        //spec| Step3
        //spec| Verify that the value of C.type is webauthn.create.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.CREATE)) {
            throw new MaliciousDataException("ClientData.type must be 'create' on registration, but it isn't.");
        }

        //spec| Step4
        //spec| Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        challengeValidator.validate(registrationObject, collectedClientData, serverProperty);

        //spec| Step5
        //spec| Verify that the value of C.origin matches the Relying Party's origin.
        originValidator.validate(registrationObject, collectedClientData, serverProperty);

        //spec| Step6
        //spec| Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        //spec| which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
        //spec| C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        tokenBindingValidator.validate(collectedClientData.getTokenBinding(), serverProperty.getTokenBindingId());

        //spec| Step7
        //spec| Compute the hash of response.clientDataJSON using SHA-256.

        //spec| Step8
        //spec| Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
        //spec| obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.

        //spec| Step9
        //spec| Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        rpIdHashValidator.validate(registrationObject, authenticatorData.getRpIdHash(), serverProperty);


        //spec| Step10, 11
        validateUVUPFlags(authenticatorData, registrationContext.isUserVerificationRequired(), registrationContext.isUserPresenceRequired());

        //spec| Step12
        //spec| Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        //spec| extension outputs in the extensions in authData are as expected, considering the client extension input
        //spec| values that were given as the extensions option in the create() call. In particular, any extension identifier
        //spec| values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        //spec| identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        //spec| In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        List<String> expectedExtensionIdentifiers = registrationContext.getExpectedExtensionIds();
        extensionValidator.validate(clientExtensions, authenticationExtensionsAuthenticatorOutputs, expectedExtensionIdentifiers);

        //spec| Step13-16,19
        attestationValidator.validate(registrationObject);

        //spec| Step17
        //spec| Check that the credentialId is not yet registered to any other user. If registration is requested for
        //spec| a credential that is already registered to a different user, the Relying Party SHOULD fail this registration
        //spec| ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.

        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step18
        //spec| If the attestation statement attStmt verified successfully and is found to be trustworthy,
        //spec| then register the new credential with the account that was denoted in the options.user passed to create(),
        //spec| by associating it with the credential ID and credential public key contained in authData’s attestation data,
        //spec| as appropriate for the Relying Party's systems.

        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        // validate with custom logic
        for (CustomRegistrationValidator customRegistrationValidator : customRegistrationValidators) {
            customRegistrationValidator.validate(registrationObject);
        }

        return new WebAuthnRegistrationContextValidationResponse(collectedClientData, attestationObject, clientExtensions);
    }

    void validateAuthenticatorDataField(AuthenticatorData authenticatorData) {
        // attestedCredentialData must be present on registration
        if (authenticatorData.getAttestedCredentialData() == null) {
            throw new ConstraintViolationException("attestedCredentialData must not be null on registration");
        }
    }

    void validateUVUPFlags(AuthenticatorData authenticatorData, boolean isUserVerificationRequired, boolean isUserPresenceRequired) {
        //spec| Step10
        //spec| If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        if (isUserVerificationRequired && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Validator is configured to check user verified, but UV flag in authenticatorData is not set.");
        }

        //spec| Step11
        //spec| Verify that the User Present bit of the flags in authData is set.
        if (isUserPresenceRequired && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Validator is configured to check user present, but UP flag in authenticatorData is not set.");
        }
    }

    public List<CustomRegistrationValidator> getCustomRegistrationValidators() {
        return customRegistrationValidators;
    }
}
