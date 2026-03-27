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

package com.webauthn4j.verifier;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.CoreRegistrationData;
import com.webauthn4j.data.CoreRegistrationParameters;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import com.webauthn4j.verifier.exception.NotAllowedAlgorithmException;
import com.webauthn4j.verifier.exception.UserNotPresentException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;
import com.webauthn4j.verifier.internal.BeanAssertUtil;
import com.webauthn4j.verifier.internal.RpIdHashVerifier;
import org.jetbrains.annotations.NotNull;

import java.util.List;

/**
 * Core verifier for registration ceremonies (WebAuthn-agnostic portions).
 * <p>
 * This class implements the generic portions of the verification procedure defined in the WebAuthn specification,
 * excluding WebAuthn-specific client data validation (which is handled by {@link RegistrationDataVerifier}).
 * <ul>
 *   <li>WebAuthn Level 3 (W3C Recommendation):
 *       <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">
 *       § 7.1 Registering a New Credential</a></li>
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/">Web Authentication: An API for accessing Public Key Credentials - Level 3</a>
 * @see RegistrationDataVerifier
 */
public class CoreRegistrationDataVerifier {

    // ~ Instance fields
    // ================================================================================================

    private final AuthenticatorExtensionVerifier authenticatorExtensionVerifier = new AuthenticatorExtensionVerifier();
    private final AttestationVerifier attestationVerifier;
    private final List<CustomCoreRegistrationVerifier> customRegistrationVerifiers;

    public CoreRegistrationDataVerifier(
            @NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
            @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
            @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
            @NotNull List<CustomCoreRegistrationVerifier> customRegistrationVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementVerifiers, "attestationStatementVerifiers must not be null");
        AssertUtil.notNull(certPathTrustworthinessVerifier, "certPathTrustworthinessVerifier must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessVerifier, "selfAttestationTrustworthinessVerifier must not be null");
        AssertUtil.notNull(customRegistrationVerifiers, "customRegistrationVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.attestationVerifier = new AttestationVerifier(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier);
        this.customRegistrationVerifiers = customRegistrationVerifiers;
    }


    /**
     * It is up to caller responsibility to inject challenge into clientData and verify it equals to challenge stored in server side
     *
     * @param registrationData       registration data
     * @param registrationParameters registration parameters
     */
    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    public void verify(@NotNull CoreRegistrationData registrationData, @NotNull CoreRegistrationParameters registrationParameters) {

        //spec| Step1
        //spec| Let options be a new CredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
        //spec| Let pkOptions be options.publicKey.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step2
        //spec| Call navigator.credentials.create() and pass options as the argument. Let credential be the result of the successfully resolved promise.
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
        //      (This step is only applicable to WebAuthn)

        //spec| Step5
        //spec| Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        //      (This step is only applicable to WebAuthn)

        BeanAssertUtil.validate(registrationData);
        AssertUtil.notNull(registrationParameters, "registrationParameters must not be null");

        //spec| Step6
        //spec| Let C, the client data claimed as collected during the credential creation,
        //spec| be the result of running an implementation-specific JSON parser on JSONtext.
        //      (This step is only applicable to WebAuthn)

        AttestationObject attestationObject = registrationData.getAttestationObject();


        verifyAuthenticatorDataField(attestationObject.getAuthenticatorData());

        CoreServerProperty serverProperty = registrationParameters.getServerProperty();

        CoreRegistrationObject registrationObject = createCoreRegistrationObject(registrationData, registrationParameters);

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();

        COSEKey coseKey = authenticatorData.getAttestedCredentialData().getCOSEKey();
        verifyCOSEKey(coseKey);

        //spec| Step7
        //spec| Verify that the value of C.type is webauthn.create.
        //      (This step is only applicable to WebAuthn)

        //spec| Step8
        //spec| Verify that the value of C.challenge equals the base64url encoding of pkOptions.challenge.
        //      (This step is only applicable to WebAuthn)


        //spec| Step9
        //spec| Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
        //      (This step is only applicable to WebAuthn)

        //spec| Step10 & Step11
        //spec| If C.crossOrigin is present and set to true, verify that the Relying Party expects this credential to be created within an iframe that is not same-origin with its ancestors.
        //spec| If C.topOrigin is present:
        //spec| - Verify that the Relying Party expects this credential to be created within an iframe that is not same-origin with its ancestors.
        //spec| - Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within.
        //      (This step is only applicable to WebAuthn)

        //spec| Step12
        //spec| Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
        //      (CoreRegistrationDataVerifier receives clientDataHash from caller.)

        //spec| Step13
        //spec| Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
        //spec| obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
        //      (This step is done on caller.)

        //spec| Step14
        //spec| Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        RpIdHashVerifier.verify(authenticatorData.getRpIdHash(), serverProperty);

        //spec| Step15
        //spec| If options.mediation is not set to conditional, verify that the UP bit of the flags in authData is set.
        //      Note: It is caller's responsibility to configure userPresenceRequired parameter based on the mediation type.
        //spec| Step16
        //spec| If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
        verifyUVUPFlags(authenticatorData, registrationParameters.isUserVerificationRequired(), registrationParameters.isUserPresenceRequired());

        //spec| Step17
        //spec| If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        //      (This step is not implemented in CoreRegistrationDataVerifier. It's caller's responsibility if needed.)

        //spec| Step18
        //spec| If the Relying Party uses the credential's backup eligibility to inform its user experience flows and/or policies,
        //spec| evaluate the BE bit of the flags in authData.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step19
        //spec| If the Relying Party uses the credential's backup state to inform its user experience flows and/or policies,
        //spec| evaluate the BS bit of the flags in authData.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step20
        //spec| Verify that the "alg" parameter in the credential public key in authData
        //spec| matches the alg attribute of one of the items in pkOptions.pubKeyCredParams.
        COSEAlgorithmIdentifier alg = authenticatorData.getAttestedCredentialData().getCOSEKey().getAlgorithm();
        List<PublicKeyCredentialParameters> pubKeyCredParams = registrationParameters.getPubKeyCredParams();
        verifyAlg(alg, pubKeyCredParams);

        //spec| Step21-23
        //spec| Determine attestation statement format, verify attestation statement, and assess attestation trustworthiness.
        attestationVerifier.verify(registrationObject);

        //spec| Step24
        //spec| Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
        //      (This step is implemented in RegistrationDataVerifier but not in CoreRegistrationDataVerifier.)

        //spec| Step25
        //spec| Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step26
        //spec| Let credentialRecord be a new credential record with the following contents:
        //spec| with contents:
        //spec| type: credential.type
        //spec| id: credential.id or credential.rawId, whichever format is preferred by the Relying Party
        //spec| publicKey: The credential public key in authData
        //spec| signCount: authData.signCount
        //spec| uvInitialized: The value of the UV flag in authData
        //spec| transports: The value returned from response.getTransports()
        //spec| backupEligible: The value of the BE flag in authData
        //spec| backupState: The value of the BS flag in authData
        //spec| The new credential record MAY also include OPTIONAL contents:
        //spec| attestationObject, attestationClientDataJSON, rpId
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step27
        //spec| Process the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData
        //spec| as required by the Relying Party. Depending on each extension, processing steps may be concretely specified or it may be up to the
        //spec| Relying Party what to do with extension outputs. The Relying Party MAY ignore any or all extension outputs.
        //spec| Clients MAY set additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension
        //spec| outputs or client extension outputs that were not requested by the Relying Party in pkOptions.extensions.
        //spec| The Relying Party MUST be prepared to handle such situations, whether by ignoring the unsolicited extensions or by rejecting the attestation.
        //spec| The Relying Party can make this decision based on local policy and the extensions in use.
        //spec| Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases
        //spec| where none or not all of the requested extensions were acted upon.
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        authenticatorExtensionVerifier.verify(authenticationExtensionsAuthenticatorOutputs);

        //spec| Step28
        //spec| If all the above steps are successful, store credentialRecord in the user account that was denoted in pkOptions.user
        //spec| and continue the registration ceremony as appropriate. Otherwise, fail the registration ceremony.

        //      (Step28 continuation: Custom verification logic)
        for (CustomCoreRegistrationVerifier customRegistrationVerifier : customRegistrationVerifiers) {
            customRegistrationVerifier.verify(registrationObject);
        }
    }

    void verifyAlg(COSEAlgorithmIdentifier alg, List<PublicKeyCredentialParameters> pubKeyCredParams) {
        if(pubKeyCredParams != null && pubKeyCredParams.stream().noneMatch(item -> item.getAlg().equals(alg))){
            List<COSEAlgorithmIdentifier> expected = pubKeyCredParams.stream()
                    .map(PublicKeyCredentialParameters::getAlg)
                    .toList();
            throw new NotAllowedAlgorithmException("alg not listed in pkOptions.pubKeyCredParams is used.", expected, alg);
        }
    }

    void verifyCOSEKey(COSEKey coseKey) {
        if (coseKey.getPublicKey() == null) {
            throw new ConstraintViolationException("coseKey doesn't contain public key");
        }
    }

    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    protected CoreRegistrationObject createCoreRegistrationObject(@NotNull CoreRegistrationData registrationData, @NotNull CoreRegistrationParameters registrationParameters) {
        return new CoreRegistrationObject(
                registrationData.getAttestationObject(),
                registrationData.getAttestationObjectBytes(),
                registrationData.getClientDataHash(),
                registrationParameters.getServerProperty()
        );
    }

    void verifyAuthenticatorDataField(@NotNull AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData) {
        // attestedCredentialData must be present on registration
        if (authenticatorData.getAttestedCredentialData() == null) {
            throw new ConstraintViolationException("attestedCredentialData must not be null on registration");
        }
    }

    void verifyUVUPFlags(@NotNull AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData, boolean isUserVerificationRequired, boolean isUserPresenceRequired) {
        // Verify that the UP bit of the flags in authData is set (if required by configuration).
        if (isUserPresenceRequired && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Verifier is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        // Determine whether user verification is required for this operation.
        // If user verification is required, verify that the UV bit of the flags in authData is set.
        if (isUserVerificationRequired && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Verifier is configured to check user verified, but UV flag in authenticatorData is not set.");
        }
    }

    public @NotNull List<CustomCoreRegistrationVerifier> getCustomRegistrationVerifiers() {
        return customRegistrationVerifiers;
    }

}
