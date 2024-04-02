/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.*;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public class RegistrationDataValidator {

    private static final int DEFAULT_MAX_CREDENTIAL_ID_LENGTH = 1023;

    // ~ Instance fields
    // ================================================================================================
    private final ChallengeValidator challengeValidator = new ChallengeValidator();
    private final TokenBindingValidator tokenBindingValidator = new TokenBindingValidator();
    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private final ClientExtensionValidator clientExtensionValidator = new ClientExtensionValidator();
    private final AuthenticatorExtensionValidator authenticatorExtensionValidator = new AuthenticatorExtensionValidator();

    private final List<CustomRegistrationValidator> customRegistrationValidators;

    private final AttestationValidator attestationValidator;

    private OriginValidator originValidator = new OriginValidatorImpl();

    private int maxCredentialIdLength = DEFAULT_MAX_CREDENTIAL_ID_LENGTH;

    public RegistrationDataValidator(
            @NonNull List<AttestationStatementValidator> attestationStatementValidators,
            @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            @NonNull SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
            @NonNull List<CustomRegistrationValidator> customRegistrationValidators,
            @NonNull ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");
        AssertUtil.notNull(customRegistrationValidators, "customRegistrationValidators must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.attestationValidator = new AttestationValidator(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator);

        this.customRegistrationValidators = customRegistrationValidators;
    }

    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    public void validate(@NonNull RegistrationData registrationData, @NonNull RegistrationParameters registrationParameters) {

        //spec| Step1
        //spec| Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step2
        //spec| Call navigator.credentials.create() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise.
        //spec| If the promise is rejected, abort the ceremony with a user-visible error,
        //spec| or otherwise guide the user experience as might be determinable from the context available in the rejected promise.
        //spec| For example if the promise is rejected with an error code equivalent to "InvalidStateError",
        //spec| the user might be instructed to use a different authenticator.
        //spec| For information on different error contexts and the circumstances leading to them, see § 6.3.2 The authenticatorMakeCredential Operation.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step3
        //spec| Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step4
        //spec| Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

        //spec| Step5
        //spec| Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        //      (This step is done on caller.)

        BeanAssertUtil.validate(registrationData);
        AssertUtil.notNull(registrationParameters, "registrationParameters must not be null");

        byte[] clientDataBytes = registrationData.getCollectedClientDataBytes();
        byte[] attestationObjectBytes = registrationData.getAttestationObjectBytes();

        //spec| Step6
        //spec| Let C, the client data claimed as collected during the credential creation,
        //spec| be the result of running an implementation-specific JSON parser on JSONtext.
        CollectedClientData collectedClientData = registrationData.getCollectedClientData();
        AttestationObject attestationObject = registrationData.getAttestationObject();
        Set<AuthenticatorTransport> transports = registrationData.getTransports();

        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = registrationData.getClientExtensions();

        validateAuthenticatorDataField(attestationObject.getAuthenticatorData());

        ServerProperty serverProperty = registrationParameters.getServerProperty();

        RegistrationObject registrationObject = new RegistrationObject(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                transports,
                serverProperty
        );

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();

        //spec| Step7
        //spec| Verify that the value of C.type is webauthn.create.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.WEBAUTHN_CREATE)) {
            throw new InconsistentClientDataTypeException("ClientData.type must be 'create' on registration, but it isn't.");
        }

        //spec| Step8
        //spec| Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        challengeValidator.validate(collectedClientData, serverProperty);

        //spec| Step9
        //spec| Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
        originValidator.validate(registrationObject);

        //spec| (Level2) Step10 (Kept for backward compatibility)
        //spec| Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        //spec| which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
        //spec| C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        tokenBindingValidator.validate(collectedClientData.getTokenBinding(), serverProperty.getTokenBindingId());

        //spec| Step10
        //spec| If C.topOrigin is present:
        //spec|   - Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors.
        //spec|   - Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See § 13.4.9 Validating the origin of a credential for guidance.
        //TODO: Once Chrome starts supporting topOrigin, implement topOrigin verification

        //spec| Step11
        //spec| Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.

        //spec| Step12
        //spec| Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
        //spec| obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
        //      (This step is done on caller.)

        //spec| Step13
        //spec| Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), serverProperty);

        //spec| Step14, 15
        //spec| Verify that the UP bit of the flags in authData is set.
        //spec| If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
        validateUVUPFlags(authenticatorData, registrationParameters.isUserVerificationRequired(), registrationParameters.isUserPresenceRequired());

        //spec| Step16
        //spec| If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        validateBEBSFlags(authenticatorData);

        //spec| Step17
        //spec| If the Relying Party uses the credential’s backup eligibility to inform its user experience flows and/or policies, evaluate the BE bit of the flags in authData.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step18
        //spec| If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies, evaluate the BS bit of the flags in authData.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)


        //spec| Step19
        //spec| Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
        COSEAlgorithmIdentifier alg = authenticatorData.getAttestedCredentialData().getCOSEKey().getAlgorithm();
        List<PublicKeyCredentialParameters> pubKeyCredParams = registrationParameters.getPubKeyCredParams();
        validateAlg(alg, pubKeyCredParams);

        //spec| Step20
        //spec| Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected,
        //spec| considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions,
        //spec| i.e., those that were not specified as part of options.extensions.
        //spec| In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        clientExtensionValidator.validate(clientExtensions);
        authenticatorExtensionValidator.validate(authenticationExtensionsAuthenticatorOutputs);

        //spec| Step21-24, 28
        attestationValidator.validate(registrationObject);

        //spec| Step25
        //spec| Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
        validateCredentialIdLength(attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId());

        //spec| Step26
        //spec| Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step27
        //spec| If the attestation statement attStmt verified successfully and is found to be trustworthy,
        //spec| then create and store a new credential record in the user account that was denoted in options.user,
        //spec| with the following contents:
        //spec| type
        //spec|     credential.type.
        //spec| id
        //spec|     credential.id or credential.rawId, whichever format is preferred by the Relying Party.
        //spec| publicKey
        //spec|     The credential public key in authData.
        //spec| signCount
        //spec|     authData.signCount.
        //spec| uvInitialized
        //spec|     The value of the UV flag in authData.
        //spec| transports
        //spec|     The value returned from response.getTransports().
        //spec| backupEligible
        //spec|     The value of the BE flag in authData.
        //spec| backupState
        //spec|     The value of the BS flag in authData.
        //spec| The new credential record MAY also include the following OPTIONAL contents:
        //spec| attestationObject
        //spec|     response.attestationObject.
        //spec| attestationClientDataJSON
        //spec|     response.clientDataJSON.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step28
        //spec| If the attestation statement attStmt successfully verified but is not trustworthy per step 23 above,
        //spec| the Relying Party SHOULD fail the registration ceremony.
        //      (This step is implemented in attestationValidator#validate)

        // validate with custom logic
        for (CustomRegistrationValidator customRegistrationValidator : customRegistrationValidators) {
            customRegistrationValidator.validate(registrationObject);
        }
    }

    void validateAlg(COSEAlgorithmIdentifier alg, List<PublicKeyCredentialParameters> pubKeyCredParams) {
        if(pubKeyCredParams != null && pubKeyCredParams.stream().noneMatch(item -> item.getAlg().equals(alg))){
            throw new NotAllowedAlgorithmException("alg not listed in options.pubKeyCredParams is used.");
        }
    }

    void validateAuthenticatorDataField(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        // attestedCredentialData must be present on registration
        if (authenticatorData.getAttestedCredentialData() == null) {
            throw new ConstraintViolationException("attestedCredentialData must not be null on registration");
        }
    }

    void validateUVUPFlags(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData, boolean isUserVerificationRequired, boolean isUserPresenceRequired) {
        //spec| Step14
        //spec| Verify that the User Present bit of the flags in authData is set.
        //      Administrator can allow UP=false condition
        if (isUserPresenceRequired && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Validator is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        //spec| Step15
        //spec| If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
        if (isUserVerificationRequired && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Validator is configured to check user verified, but UV flag in authenticatorData is not set.");
        }
    }

    void validateBEBSFlags(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        if(!authenticatorData.isFlagBE() && authenticatorData.isFlagBS()){
            throw new IllegalBackupStateException("Backup state bit must not be set if backup eligibility bit is not set");
        }
    }

    void validateCredentialIdLength(byte[] credentialId) {
        if(maxCredentialIdLength >= 0 && credentialId.length > maxCredentialIdLength){
            throw new CredentialIdTooLongException(String.format("credentialId exceeds maxCredentialIdSize(%d bytes)", maxCredentialIdLength));
        }
    }

    public OriginValidator getOriginValidator() {
        return originValidator;
    }

    public void setOriginValidator(OriginValidator originValidator) {
        this.originValidator = originValidator;
    }

    public int getMaxCredentialIdLength() {
        return maxCredentialIdLength;
    }

    public void setMaxCredentialIdLength(int maxCredentialIdLength) {
        this.maxCredentialIdLength = maxCredentialIdLength;
    }

    public List<CustomRegistrationValidator> getCustomRegistrationValidators() {
        return customRegistrationValidators;
    }

}
