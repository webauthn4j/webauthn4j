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


import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.AttestationType;
import com.webauthn4j.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.ClientExtensionOutputsConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.fido.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.NullECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.MaliciousDataException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * {@inheritDoc}
 */
public class WebAuthnRegistrationContextValidator {

    // ~ Instance fields
    // ================================================================================================

    private final List<AttestationStatementValidator> attestationStatementValidators;
    private final CertPathTrustworthinessValidator certPathTrustworthinessValidator;
    private final ECDAATrustworthinessValidator ecdaaTrustworthinessValidator;
    private final SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;

    private final ChallengeValidator challengeValidator = new ChallengeValidator();
    private final OriginValidator originValidator = new OriginValidator();
    private final TokenBindingValidator tokenBindingValidator = new TokenBindingValidator();
    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();

    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter();
    private final ClientExtensionOutputsConverter clientExtensionOutputsConverter = new ClientExtensionOutputsConverter();
    private final ExtensionValidator extensionValidator = new ExtensionValidator();

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
            SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator
    ) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(ecdaaTrustworthinessValidator, "ecdaaTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");

        this.attestationStatementValidators = attestationStatementValidators;
        this.certPathTrustworthinessValidator = certPathTrustworthinessValidator;
        this.ecdaaTrustworthinessValidator = ecdaaTrustworthinessValidator;
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator
    ) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                new DefaultSelfAttestationTrustworthinessValidator()
        );
    }

    public static WebAuthnRegistrationContextValidator createNullAttestationStatementValidator() {
        return new WebAuthnRegistrationContextValidator(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new NullFIDOU2FAttestationStatementValidator(),
                        new NullPackedAttestationStatementValidator())
                ,
                new NullCertPathTrustworthinessValidator(),
                new NullECDAATrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator()
        );
    }

    // ~ Methods
    // ========================================================================================================

    public void validate(WebAuthnRegistrationContext registrationContext) {

        BeanAssertUtil.validate(registrationContext);

        byte[] clientDataBytes = registrationContext.getClientDataJSON();
        byte[] attestationObjectBytes = registrationContext.getAttestationObject();

        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        Map<String, ClientExtensionOutput> clientExtensionOutputs =
                clientExtensionOutputsConverter.convert(registrationContext.getClientExtensionsJSON());

        BeanAssertUtil.validate(collectedClientData);
        BeanAssertUtil.validate(attestationObject);
        BeanAssertUtil.validateClientExtensionsOutputs(clientExtensionOutputs);

        RegistrationObject registrationObject = new RegistrationObject(
                collectedClientData,
                clientDataBytes,
                attestationObject,
                attestationObjectBytes,
                registrationContext.getServerProperty()
        );

        AuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();
        ServerProperty serverProperty = registrationContext.getServerProperty();

        // Verify that the value of C.type is webauthn.create.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.CREATE)) {
            throw new MaliciousDataException("Bad client data type");
        }

        /// Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
        challengeValidator.validate(collectedClientData, serverProperty);

        /// Verify that the value of C.origin matches the Relying Party's origin.
        originValidator.validate(collectedClientData, serverProperty);

        /// Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        /// which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
        /// C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        tokenBindingValidator.validate(collectedClientData.getTokenBinding(), serverProperty.getTokenBindingId());

        /// Compute the hash of response.clientDataJSON using SHA-256.

        /// Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
        /// obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.

        /// Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), serverProperty);

        /// If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
        if (registrationContext.isUserVerificationRequired() && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("User not verified");
        }

        /// If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.
        if (!registrationContext.isUserVerificationRequired() && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("User not present");
        }

        /// Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        /// extension outputs in the extensions in authData are as expected, considering the client extension input
        /// values that were given as the extensions option in the create() call. In particular, any extension identifier
        /// values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        /// identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        /// In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        Map<String, AuthenticatorExtensionOutput> authenticatorExtensionOutputs = authenticatorData.getExtensions();
        List<String> expectedExtensionIdentifiers = registrationContext.getExpectedExtensionIds();
        extensionValidator.validate(clientExtensionOutputs, authenticatorExtensionOutputs, expectedExtensionIdentifiers);


        /// Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set
        /// of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered
        /// WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same
        /// name [WebAuthn-Registries].

        /// Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the
        /// attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the
        /// serialized client data computed in step 7.

        /// Note: Each attestation statement format specifies its own verification procedure. See §8 Defined Attestation
        /// Statement Formats for the initially-defined formats, and  [WebAuthn-Registries] for the up-to-date list.
        AttestationType attestationType = validateAttestationStatement(registrationObject);

        /// If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or
        /// ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt,
        /// from a trusted source or from policy.
        /// For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        /// using the aaguid in the attestedCredentialData in authData.
        ///
        /// Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:

        AttestationStatement attestationStatement = attestationObject.getAttestationStatement();
        switch (attestationType) {
            // If self attestation was used, check if self attestation is acceptable under Relying Party policy.
            case SELF:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    selfAttestationTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                } else {
                    throw new IllegalStateException();
                }
                break;

            // If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of
            // acceptable trust anchors obtained in step 15.
            case ECDAA:
                ecdaaTrustworthinessValidator.validate(attestationStatement);
                break;
            // Otherwise, use the X.509 certificates returned by the verification procedure to verify that
            // the attestation public key correctly chains up to an acceptable root certificate.
            case BASIC:
            case ATT_CA:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    certPathTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                } else {
                    throw new IllegalStateException();
                }
                break;
            case NONE:
                // nop
                break;
            default:
                throw new NotImplementedException();
        }

        // If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in the options.user passed to create(),
        // by associating it with the credential ID and credential public key contained in authData’s attestation data,
        // as appropriate for the Relying Party's systems.

        /// Check that the credentialId is not yet registered to any other user. If registration is requested for
        /// a credential that is already registered to a different user, the Relying Party SHOULD fail this registration
        /// ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.

        // ******* This step is up to library user *******

    }

    private AttestationType validateAttestationStatement(RegistrationObject registrationObject) {
        for (AttestationStatementValidator validator : attestationStatementValidators) {
            if (validator.supports(registrationObject)) {
                return validator.validate(registrationObject);
            }
        }

        throw new BadAttestationStatementException("Supplied AttestationStatement format is not configured.");
    }
}
