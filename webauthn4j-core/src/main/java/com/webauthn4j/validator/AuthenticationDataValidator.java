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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.credential.CoreCredentialRecord;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class AuthenticationDataValidator {

    private final ChallengeVerifier challengeVerifier = new ChallengeVerifier();
    private final TokenBindingVerifier tokenBindingVerifier = new TokenBindingVerifier();
    private final RpIdHashVerifier rpIdHashVerifier = new RpIdHashVerifier();
    private final AssertionSignatureValidator assertionSignatureValidator = new AssertionSignatureValidator();
    private final ClientExtensionVerifier clientExtensionVerifier = new ClientExtensionVerifier();
    private final AuthenticatorExtensionVerifier authenticatorExtensionVerifier = new AuthenticatorExtensionVerifier();

    private final List<CustomAuthenticationValidator> customAuthenticationValidators;

    private OriginValidator originValidator = new OriginValidatorImpl();
    private CoreMaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultCoreMaliciousCounterValueHandler();

    private boolean crossOriginAllowed = false;

    public AuthenticationDataValidator(@NotNull List<CustomAuthenticationValidator> customAuthenticationValidators) {
        AssertUtil.notNull(customAuthenticationValidators, "customAuthenticationValidators must not be null");
        this.customAuthenticationValidators = customAuthenticationValidators;
    }

    public AuthenticationDataValidator() {
        this.customAuthenticationValidators = new ArrayList<>();
    }

    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    public void validate(@NotNull AuthenticationData authenticationData, @NotNull AuthenticationParameters authenticationParameters) {

        BeanAssertUtil.validate(authenticationData);
        AssertUtil.notNull(authenticationParameters, "authenticationParameters must not be null");

        //spec| Step1
        //spec| Let options be a new PublicKeyCredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.
        //      (This step is done on client slide and out of WebAuthn4J responsibility.)

        //spec| Step2
        //spec| Call navigator.credentials.get() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise.
        //spec| If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable
        //spec| from the context available in the rejected promise. For information on different error contexts and the circumstances leading to them,
        //spec| see § 6.3.3 The authenticatorGetAssertion Operation.
        //      (This step is done on client slide and out of WebAuthn4J responsibility.)

        //spec| Step3
        //spec| Let response be credential.response. If response is not an instance of AuthenticatorAssertionResponse, abort the ceremony with a user-visible error.
        //      (This step is done on client slide and out of WebAuthn4J responsibility.)

        //spec| Step4
        //spec| Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions = authenticationData.getClientExtensions();

        //spec| Step5
        //spec| If options.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in options.allowCredentials.
        byte[] credentialId = authenticationData.getCredentialId();
        List<byte[]> allowCredentials = authenticationParameters.getAllowCredentials();
        validateCredentialId(credentialId, allowCredentials);

        //spec| Step6
        //spec| Identify the user being authenticated and let credentialRecord be the credential record for the credential:
        //spec| - If the user was identified before the authentication ceremony was initiated, e.g., via a username or cookie,
        //spec|   verify that the identified user account contains a credential record whose id equals credential.rawId.
        //spec|   Let credentialRecord be that credential record. If response.userHandle is present,
        //spec|   verify that it equals the user handle of the user account.
        //spec| - If the user was not identified before the authentication ceremony was initiated,
        //spec|   verify that response.userHandle is present. Verify that the user account identified by response.userHandle
        //spec|   contains a credential record whose id equals credential.rawId. Let credentialRecord be that credential record.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        // Step7-8 is missing in the WebAuthn Level3 specification

        //spec| Step9
        //spec| Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case),
        //spec| look up the corresponding credential public key and let credentialPublicKey be that credential public key.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step9
        //spec| Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData,
        //spec| and signature respectively.
        byte[] cData = authenticationData.getCollectedClientDataBytes();
        byte[] aData = authenticationData.getAuthenticatorDataBytes();

        //spec| Step10
        //spec| Let JSONtext be the result of running UTF-8 decode on the value of cData.
        //      (This step is done on caller.)

        //spec| Step11
        //spec| Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
        //      (In the spec, claimed as "C", but use "collectedClientData" here)
        CollectedClientData collectedClientData = authenticationData.getCollectedClientData();

        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        ServerProperty serverProperty = authenticationParameters.getServerProperty();

        BeanAssertUtil.validate(collectedClientData);
        BeanAssertUtil.validate(authenticatorData);

        validateAuthenticatorData(authenticatorData);

        Authenticator authenticator = authenticationParameters.getAuthenticator();

        AuthenticationObject authenticationObject = new AuthenticationObject(
                credentialId, authenticatorData, aData, collectedClientData, cData, clientExtensions,
                serverProperty, authenticator
        );

        //spec| Step12
        //spec| Verify that the value of C.type is the string webauthn.get.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.WEBAUTHN_GET)) {
            throw new InconsistentClientDataTypeException("ClientData.type must be 'get' on authentication, but it isn't.");
        }

        //spec| Step13
        //spec| Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        challengeVerifier.verify(collectedClientData, serverProperty);

        //spec| Step14
        //spec| Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
        originValidator.validate(authenticationObject);

        // Verify cross origin, which is not defined in the spec
        validateClientDataCrossOrigin(collectedClientData);

        //spec| Step15
        //spec| If C.topOrigin is present:
        //spec| - Verify that the Relying Party expects this credential to be used within an iframe that is not same-origin with its ancestors.
        //spec| - Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within.
        //spec|   See §13.4.9 Validating the origin of a credential for guidance.
        //TODO: Once Chrome starts supporting topOrigin, implement topOrigin verification

        //spec| (Level2) Step14 (Kept for backward compatibility)
        //spec| Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        //spec| which the attestation was obtained. If Token Binding was used on that TLS connection,
        //spec| also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        tokenBindingVerifier.verify(collectedClientData.getTokenBinding(), serverProperty.getTokenBindingId());

        //spec| Step16
        //spec| Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        rpIdHashVerifier.verify(authenticatorData.getRpIdHash(), serverProperty);

        //spec| Step17
        //spec| Verify that the UP bit of the flags in authData is set.
        if (authenticationParameters.isUserPresenceRequired() && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Validator is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        //spec| Step18
        //spec| Determine whether user verification is required for this assertion.
        //spec| User verification SHOULD be required if, and only if, options.userVerification is set to required.
        //spec| If user verification was determined to be required, verify that the UV bit of the flags in authData is set.
        //spec| Otherwise, ignore the value of the UV flag.
        if (authenticationParameters.isUserVerificationRequired() && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Validator is configured to check user verified, but UV flag in authenticatorData is not set.");
        }

        //spec| Step19
        //spec| If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        validateBEBSFlags(authenticatorData);

        //spec| Step20
        //spec| If the credential backup state is used as part of Relying Party business logic or policy,
        //spec| let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
        //spec| Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
        //spec| - If credentialRecord.backupEligible is set, verify that currentBe is set.
        //spec| - If credentialRecord.backupEligible is not set, verify that currentBe is not set.
        //spec| - Apply Relying Party policy, if any.
        //      (The relying party policy should be implemented as a custom validator)
        validateBEFlag(authenticator, authenticatorData);

        //spec| Step21
        //spec| Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        //spec| extension outputs in the extensions in authData are as expected, considering the client extension input
        //spec| values that were given as the extensions option in the get() call. In particular, any extension identifier
        //spec| values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        //spec| identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        //spec| In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        clientExtensionVerifier.verify(clientExtensions);
        authenticatorExtensionVerifier.verify(authenticationExtensionsAuthenticatorOutputs);

        //spec| Step22
        //spec| Let hash be the result of computing a hash over the cData using SHA-256.
        //spec| Step23
        //spec| Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
        assertionSignatureValidator.validate(authenticationData, authenticator.getAttestedCredentialData().getCOSEKey());

        //spec| Step24
        //spec| If authData.signCount is nonzero or credentialRecord.signCount is nonzero, then run the following sub-step:
        long presentedSignCount = authenticatorData.getSignCount();
        long storedSignCount = authenticator.getCounter();
        if (presentedSignCount > 0 || storedSignCount > 0) {
            //spec| If authData.signCount is
            //spec| greater than credentialRecord.signCount:
            if (presentedSignCount > storedSignCount) {

                //spec| The signature counter is valid.
                //no-op
            }
            //spec| less than or equal to credentialRecord.signCount:
            //spec| This is a signal that the authenticator may be cloned,
            //spec| i.e. at least two copies of the credential private key may exist and are being used in parallel.
            //spec| Relying Parties should incorporate this information into their risk scoring.
            //spec| Whether the Relying Party updates credentialRecord.signCount below in this case, or not, or
            //spec| fails the authentication ceremony or not, is Relying Party-specific.
            else {
                maliciousCounterValueHandler.maliciousCounterValueDetected(authenticationObject);
            }
        }

        //spec| Step25
        //spec| If response.attestationObject is present and the Relying Party wishes to verify the attestation
        //spec| then perform CBOR decoding on attestationObject to obtain the attestation statement format fmt, and the attestation statement attStmt.
        //spec| - Verify that the AT bit in the flags field of authData is set, indicating that attested credential data is included.
        //spec| - Verify that the credentialPublicKey and credentialId fields of the attested credential data in authData match
        //spec|   credentialRecord.publicKey and credentialRecord.id, respectively.
        //spec| - Determine the attestation statement format by performing a USASCII case-sensitive match on
        //spec|   fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
        //spec|   An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in
        //spec|   the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
        //spec| - Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
        //spec|   by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
        //TODO: Since Step25 is removed in the latest Editor's draft(as of 2024-04-07, see https://github.com/w3c/webauthn/pull/1997), this step is left not implemented. This step need to be removed when the next draft is released.

        //spec| Step26
        //spec| Update credentialRecord with new state values:
        //spec| - Update credentialRecord.signCount to the value of authData.signCount.
        //spec| - Update credentialRecord.backupState to the value of currentBs.
        //spec| - If credentialRecord.uvInitialized is false, update it to the value of the UV bit in the flags in authData. This change SHOULD require authorization by an additional authentication factor equivalent to WebAuthn user verification; if not authorized, skip this step.
        updateRecord(authenticator, authenticatorData);

        //spec| - OPTIONALLY, if response.attestationObject is present, update credentialRecord.attestationObject to the value of response.attestationObject and update credentialRecord.attestationClientDataJSON to the value of response.clientDataJSON.
        //TODO: Since this optional step is removed in the latest Editor's draft(as of 2024-04-07), this step is left not implemented. This step need to be removed when the next draft is released.

        //spec| If the Relying Party performs additional security checks beyond these WebAuthn authentication ceremony steps, the above state updates SHOULD be deferred to after those additional checks are completed successfully.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        for (CustomAuthenticationValidator customAuthenticationValidator : customAuthenticationValidators) {
            customAuthenticationValidator.validate(authenticationObject);
        }

        //spec| Step27
        //spec| If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.


    }

    static void validateBEFlag(Authenticator authenticator, AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if(authenticator instanceof CoreCredentialRecord){
            CoreCredentialRecord coreCredentialRecord = (CoreCredentialRecord) authenticator;
            Boolean backEligibleRecordValue = coreCredentialRecord.isBackupEligible();
            //noinspection StatementWithEmptyBody
            if(backEligibleRecordValue == null){
                //no-op
            }
            else if(backEligibleRecordValue) {
                if(!authenticatorData.isFlagBE()){
                    throw new BadBackupEligibleFlagException("Although credential record BE flag is set, current BE flag is not set");
                }
            }
            else{
                if(authenticatorData.isFlagBE()){
                    throw new BadBackupEligibleFlagException("Although credential record BE flag is not set, current BE flag is set");
                }
            }
        }
    }

    static void updateRecord(Authenticator authenticator, AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        authenticator.setCounter(authenticatorData.getSignCount());
        if(authenticator instanceof CoreCredentialRecord){
            CoreCredentialRecord coreCredentialRecord = (CoreCredentialRecord) authenticator;

            coreCredentialRecord.setBackedUp(authenticatorData.isFlagBS());

            Boolean uvInitializedRecord = coreCredentialRecord.isUvInitialized();
            if(Objects.isNull(uvInitializedRecord) || Boolean.FALSE.equals(uvInitializedRecord)){
                coreCredentialRecord.setUvInitialized(authenticatorData.isFlagUV());
            }
        }
    }

    void validateCredentialId(byte[] credentialId, @Nullable List<byte[]> allowCredentials) {
        // As allowCredentials are known data to client side(potential attacker),
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if(allowCredentials != null && allowCredentials.stream().noneMatch(item -> Arrays.equals(item, credentialId))){
            throw new NotAllowedCredentialIdException("credentialId not listed in allowCredentials is used.");
        }
    }

    void validateClientDataCrossOrigin(CollectedClientData collectedClientData) {
        if (!crossOriginAllowed && Objects.equals(true, collectedClientData.getCrossOrigin())) {
            throw new CrossOriginException("Cross-origin request is prohibited. Relax AuthenticationDataValidator config if necessary.");
        }
    }

    void validateAuthenticatorData(@NotNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if (authenticatorData.getAttestedCredentialData() != null) {
            throw new ConstraintViolationException("attestedCredentialData must be null on authentication");
        }
    }

    void validateBEBSFlags(AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if(!authenticatorData.isFlagBE() && authenticatorData.isFlagBS()){
            throw new IllegalBackupStateException("Backup state bit must not be set if backup eligibility bit is not set");
        }
    }

    public @NotNull CoreMaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return maliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(@NotNull CoreMaliciousCounterValueHandler maliciousCounterValueHandler) {
        AssertUtil.notNull(maliciousCounterValueHandler, "maliciousCounterValueHandler must not be null");
        this.maliciousCounterValueHandler = maliciousCounterValueHandler;
    }

    public OriginValidator getOriginValidator() {
        return originValidator;
    }

    public void setOriginValidator(OriginValidator originValidator) {
        this.originValidator = originValidator;
    }

    public @NotNull List<CustomAuthenticationValidator> getCustomAuthenticationValidators() {
        return customAuthenticationValidators;
    }

    public boolean isCrossOriginAllowed() {
        return crossOriginAllowed;
    }

    public void setCrossOriginAllowed(boolean crossOriginAllowed) {
        this.crossOriginAllowed = crossOriginAllowed;
    }
}
