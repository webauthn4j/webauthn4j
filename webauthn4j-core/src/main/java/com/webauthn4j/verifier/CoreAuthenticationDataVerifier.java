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

import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.CoreAuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import com.webauthn4j.verifier.exception.NotAllowedCredentialIdException;
import com.webauthn4j.verifier.exception.UserNotPresentException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;
import com.webauthn4j.verifier.internal.AssertionSignatureVerifier;
import com.webauthn4j.verifier.internal.BeanAssertUtil;
import com.webauthn4j.verifier.internal.RpIdHashVerifier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Core authentication data verifier for FIDO assertion verification.
 * <p>
 * This class implements assertion verification based on WebAuthn Level 3 specification,
 * but with WebAuthn-specific components (CollectedClientData structure, client extensions)
 * generalized to support broader FIDO use cases.
 * <p>
 * The verification procedure follows WebAuthn Level 3 § 7.2 steps, with the following adaptations:
 * <ul>
 *   <li>Steps 10-14: Client data verification (type, challenge, origin, crossOrigin, topOrigin) - marked as WebAuthn-specific</li>
 *   <li>Step 18-19: Backup eligibility/state verification - marked as WebAuthn-specific with CoreCredentialRecord</li>
 *   <li>Step 23: Client extension verification - marked as WebAuthn-specific</li>
 *   <li>Step 24: Credential record update - deferred to caller or AuthenticationDataVerifier</li>
 * </ul>
 *
 * @see AuthenticationDataVerifier for full WebAuthn assertion verification
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2 Verifying an Authentication Assertion</a>
 */
public class CoreAuthenticationDataVerifier {

    private final AuthenticatorExtensionVerifier authenticatorExtensionVerifier = new AuthenticatorExtensionVerifier();
    private final List<CustomCoreAuthenticationVerifier> customAuthenticationVerifiers;

    private AssertionSignatureVerifier assertionSignatureVerifier = new AssertionSignatureVerifier();
    private CoreMaliciousCounterValueHandler coreMaliciousCounterValueHandler = new DefaultCoreMaliciousCounterValueHandler();

    public CoreAuthenticationDataVerifier(@NotNull List<CustomCoreAuthenticationVerifier> customAuthenticationVerifiers) {
        this.customAuthenticationVerifiers = customAuthenticationVerifiers;
    }

    public CoreAuthenticationDataVerifier() {
        this(new ArrayList<>());
    }

    protected CoreAuthenticationDataVerifier(
            @NotNull List<CustomCoreAuthenticationVerifier> customAuthenticationVerifiers,
            @NotNull AssertionSignatureVerifier assertionSignatureVerifier) {

        AssertUtil.notNull(customAuthenticationVerifiers, "customAuthenticationVerifiers must not be null");
        AssertUtil.notNull(assertionSignatureVerifier, "assertionSignatureVerifier must not be null");

        this.customAuthenticationVerifiers = customAuthenticationVerifiers;
        this.assertionSignatureVerifier = assertionSignatureVerifier;
    }

    /**
     * It is up to caller responsibility to inject challenge into clientData and verify it equals to challenge stored in server side
     *
     * @param authenticationData       authentication data
     * @param authenticationParameters authentication parameters
     */
    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    public void verify(@NotNull CoreAuthenticationData authenticationData, @NotNull CoreAuthenticationParameters authenticationParameters) {

        BeanAssertUtil.validate(authenticationData);
        AssertUtil.notNull(authenticationParameters, "authenticationParameters must not be null");

        //spec| Step1
        //spec| Let options be a new CredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.
        //spec| Let pkOptions be options.publicKey.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step2
        //spec| Call navigator.credentials.get() and pass options as the argument. Let credential be the result of the successfully resolved promise.
        //spec| If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable
        //spec| from the context available in the rejected promise. For information on different error contexts and the circumstances leading to them,
        //spec| see § 6.3.3 The authenticatorGetAssertion Operation.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step3
        //spec| Let response be credential.response. If response is not an instance of AuthenticatorAssertionResponse, abort the ceremony with a user-visible error.
        //      (This step is done on client side and out of WebAuthn4J responsibility.)

        //spec| Step4
        //spec| Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
        //      (This step is only applicable to WebAuthn)

        //spec| Step5
        //spec| If pkOptions.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials
        //spec| listed in pkOptions.allowCredentials.
        byte[] credentialId = authenticationData.getCredentialId();
        List<byte[]> allowCredentials = authenticationParameters.getAllowCredentials();
        verifyCredentialId(credentialId, allowCredentials);

        //spec| Step6
        //spec| Identify the user being authenticated and let credentialRecord be the credential record for the credential:
        //spec| - If the user was identified before the authentication ceremony was initiated, e.g., via a username or cookie,
        //spec|   verify that the identified user account contains a credential record whose id equals credential.rawId.
        //spec|   Let credentialRecord be that credential record. If response.userHandle is present,
        //spec|   verify that it equals the user handle of the user account.
        //spec| - If the user was not identified before the authentication ceremony was initiated,
        //spec|   verify that response.userHandle is present. Verify that the user account identified by response.userHandle
        //spec|   contains a credential record whose id equals credential.rawId. Let credentialRecord be that credential record.
        //      (This step is out of WebAuthn4J scope. It’s caller’s responsibility.)

        //spec| Step7
        //spec| Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and signature respectively.
        //      (This step is only applicable to WebAuthn)

        //spec| Step8
        //spec| Let JSONtext be the result of running UTF-8 decode on the value of cData.
        //      (This step is done on caller.)

        //spec| Step9
        //spec| Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
        //      (In the spec, claimed as "C", but use "collectedClientData" here)
        //      (This step is only applicable to WebAuthn)

        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        CoreServerProperty serverProperty = authenticationParameters.getServerProperty();

        BeanAssertUtil.validate(authenticatorData);

        verifyAuthenticatorData(authenticatorData);

        CoreAuthenticator authenticator = authenticationParameters.getAuthenticator();

        CoreAuthenticationObject authenticationObject = createCoreAuthenticationObject(authenticationData, authenticationParameters);

        //spec| Step10
        //spec| Verify that the value of C.type is the string webauthn.get.
        //      (This step is only applicable to WebAuthn)

        //spec| Step11
        //spec| Verify that the value of C.challenge equals the base64url encoding of pkOptions.challenge.
        //      (This step is only applicable to WebAuthn)

        //spec| Step12
        //spec| Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
        //      (This step is only applicable to WebAuthn)

        //spec| Step13 & Step14
        //spec| If C.crossOrigin is present and set to true,
        //spec| verify that the Relying Party expects this credential to be used within an iframe that is not same-origin with its ancestors.
        //spec| If C.topOrigin is present:
        //spec| - Verify that the Relying Party expects this credential to be used within an iframe that is not same-origin with its ancestors.
        //spec| - Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within.
        //spec|   See §13.4.9 Validating the origin of a credential for guidance.
        //      (This step is only applicable to WebAuthn)

        //spec| Step15
        //spec| Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        RpIdHashVerifier.verify(authenticatorData.getRpIdHash(), serverProperty);

        //spec| Step16
        //spec| Verify that the UP bit of the flags in authData is set.
        //      Note: Administrator can allow UP=false condition through configuration
        if (authenticationParameters.isUserPresenceRequired() && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Verifier is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        //spec| Step17
        //spec| Determine whether user verification is required for this assertion.
        //spec| User verification SHOULD be required if, and only if, pkOptions.userVerification is set to required.
        //spec| If user verification was determined to be required, verify that the UV bit of the flags in authData is set.
        //spec| Otherwise, ignore the value of the UV flag.
        if (authenticationParameters.isUserVerificationRequired() && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Verifier is configured to check user verified, but UV flag in authenticatorData is not set.");
        }

        //spec| Step18
        //spec| If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        //      (This step is only applicable to WebAuthn with CoreCredentialRecord)

        //spec| Step19
        //spec| If the credential backup state is used as part of Relying Party business logic or policy,
        //spec| let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
        //spec| Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
        //spec| - If credentialRecord.backupEligible is set, verify that currentBe is set.
        //spec| - If credentialRecord.backupEligible is not set, verify that currentBe is not set.
        //spec| - Apply Relying Party policy, if any.
        //      (This step is only applicable to WebAuthn with CoreCredentialRecord. The relying party policy should be implemented as a custom verifier)

        //spec| Step20 & Step21
        //spec| Let hash be the result of computing a hash over the cData using SHA-256.
        //spec|
        //spec| Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
        assertionSignatureVerifier.verify(authenticationData, authenticator.getAttestedCredentialData().getCOSEKey());

        //spec| Step22
        //spec| If authData.signCount is nonzero or credentialRecord.signCount is nonzero, then run the following sub-step:
        long presentedSignCount = authenticatorData.getSignCount();
        long storedSignCount = authenticator.getCounter();
        if (presentedSignCount > 0 || storedSignCount > 0) {
            //spec| If authData.signCount is
            //spec| greater than credentialRecord.signCount:
            if (presentedSignCount > storedSignCount) {

                //spec| The signature counter is valid.
                //      (caller need to update the signature counter value based on the value set in the Authenticator instance)
                authenticator.setCounter(presentedSignCount);
            }
            //spec| less than or equal to credentialRecord.signCount:
            //spec| This is a signal, but not proof, that the authenticator may be cloned. For example it might mean that:
            //spec| - Two or more copies of the credential private key may exist and are being used in parallel.
            //spec| - An authenticator is malfunctioning.
            //spec| - A race condition exists where the RP is processing assertion responses in an order other than the order they were generated at the authenticator.
            //spec| Relying Parties should evaluate their own operational characteristics and incorporate this information into their risk scoring.
            //spec| Whether the Relying Party updates credentialRecord.signCount below in this case, or not, or
            //spec| fails the authentication ceremony or not, is Relying Party-specific.
            else {
                coreMaliciousCounterValueHandler.maliciousCounterValueDetected(authenticationObject);
            }
        }

        //spec| Step23
        //spec| Process the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData
        //spec| as required by the Relying Party. Depending on each extension, processing steps may be concretely specified or it may be up to the
        //spec| Relying Party what to do with extension outputs. The Relying Party MAY ignore any or all extension outputs.
        //spec| Clients MAY set additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension
        //spec| outputs or client extension outputs that were not requested by the Relying Party in pkOptions.extensions.
        //spec| The Relying Party MUST be prepared to handle such situations, whether by ignoring the unsolicited extensions or by rejecting the assertion.
        //spec| The Relying Party can make this decision based on local policy and the extensions in use.
        //spec| Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases
        //spec| where none or not all of the requested extensions were acted upon.
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        //      (This clientExtensionResults verification is only applicable to WebAuthn)
        authenticatorExtensionVerifier.verify(authenticationExtensionsAuthenticatorOutputs);

        //spec| Step24
        //spec| Update credentialRecord with new state values:
        //spec| - Update credentialRecord.signCount to the value of authData.signCount.
        //spec| - Update credentialRecord.backupState to the value of currentBs.
        //spec| - If credentialRecord.uvInitialized is false, update it to the value of the UV bit in the flags in authData.
        //spec|   This change SHOULD require authorization by an additional authentication factor equivalent to WebAuthn user verification;
        //spec|   if not authorized, skip this step.
        //spec| If the Relying Party performs additional security checks beyond these WebAuthn authentication ceremony steps,
        //spec| the above state updates SHOULD be deferred to after those additional checks are completed successfully.
        //      (This step is handled by AuthenticationDataVerifier.updateRecord() in WebAuthn context)

        for (CustomCoreAuthenticationVerifier customAuthenticationVerifier : customAuthenticationVerifiers) {
            customAuthenticationVerifier.verify(authenticationObject);
        }

        //spec| Step25
        //spec| If all the above steps are successful, continue the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.

    }

    protected @NotNull CoreAuthenticationObject createCoreAuthenticationObject(@NotNull CoreAuthenticationData authenticationData, @NotNull CoreAuthenticationParameters authenticationParameters) {
        byte[] credentialId = authenticationData.getCredentialId();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        byte[] authenticatorDataBytes = authenticationData.getAuthenticatorDataBytes();
        byte[] clientDataHash = authenticationData.getClientDataHash();

        CoreServerProperty serverProperty = authenticationParameters.getServerProperty();
        CoreAuthenticator authenticator = authenticationParameters.getAuthenticator();

        AssertUtil.notNull(authenticatorData, "authenticatorData must not be null");

        return new CoreAuthenticationObject(
                credentialId, authenticatorData, authenticatorDataBytes, clientDataHash, serverProperty, authenticator
        );
    }

    void verifyCredentialId(byte[] credentialId, @Nullable List<byte[]> allowCredentials) {
        // As allowCredentials is public data(not secret data), there is no risk of timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual`
        if(allowCredentials != null && allowCredentials.stream().noneMatch(item -> Arrays.equals(item, credentialId))){
            throw new NotAllowedCredentialIdException("credentialId not listed in allowCredentials is used.");
        }
    }

    void verifyAuthenticatorData(@NotNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if (authenticatorData.getAttestedCredentialData() != null) {
            throw new ConstraintViolationException("attestedCredentialData must be null on authentication");
        }
    }

    public @NotNull CoreMaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return coreMaliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(@NotNull CoreMaliciousCounterValueHandler coreMaliciousCounterValueHandler) {
        AssertUtil.notNull(coreMaliciousCounterValueHandler, "coreMaliciousCounterValueHandler must not be null");
        this.coreMaliciousCounterValueHandler = coreMaliciousCounterValueHandler;
    }

    public @NotNull List<CustomCoreAuthenticationVerifier> getCustomAuthenticationVerifiers() {
        return customAuthenticationVerifiers;
    }
}
