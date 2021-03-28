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

import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.CoreAuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.ArrayList;
import java.util.List;

public class CoreAuthenticationDataValidator {

    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private final AuthenticatorExtensionValidator authenticatorExtensionValidator = new AuthenticatorExtensionValidator();
    private final List<CustomCoreAuthenticationValidator> customAuthenticationValidators;

    private AssertionSignatureValidator assertionSignatureValidator = new AssertionSignatureValidator();
    private CoreMaliciousCounterValueHandler coreMaliciousCounterValueHandler = new DefaultCoreMaliciousCounterValueHandler();

    public CoreAuthenticationDataValidator(@NonNull List<CustomCoreAuthenticationValidator> customAuthenticationValidators) {
        this.customAuthenticationValidators = customAuthenticationValidators;
    }

    public CoreAuthenticationDataValidator() {
        this(new ArrayList<>());
    }

    protected CoreAuthenticationDataValidator(
            @NonNull List<CustomCoreAuthenticationValidator> customAuthenticationValidators,
            @NonNull AssertionSignatureValidator assertionSignatureValidator) {

        AssertUtil.notNull(customAuthenticationValidators, "customAuthenticationValidators must not be null");
        AssertUtil.notNull(assertionSignatureValidator, "assertionSignatureValidator must not be null");

        this.customAuthenticationValidators = customAuthenticationValidators;
        this.assertionSignatureValidator = assertionSignatureValidator;
    }

    /**
     * It is up to caller responsibility to inject challenge into clientData and validate it equals to challenge stored in server side
     * @param authenticationData authentication data
     * @param authenticationParameters authentication parameters
     */
    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    public void validate(@NonNull CoreAuthenticationData authenticationData, @NonNull CoreAuthenticationParameters authenticationParameters) {

        BeanAssertUtil.validate(authenticationData);

        AssertUtil.notNull(authenticationParameters, "authenticationParameters must not be null");

        //spec| Step1
        //spec| If the allowCredentials option was given when this authentication ceremony was initiated,
        //spec| verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step2
        //spec| Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id:

        //spec| If the user was identified before the authentication ceremony was initiated,
        //spec| verify that the identified user is the owner of credentialSource.
        //spec| If credential.response.userHandle is present,
        //spec| verify that this value identifies the same user as was previously identified.
        //spec| If the user was not identified before the authentication ceremony was initiated,
        //spec| verify that credential.response.userHandle is present, and that the user identified by this value is the owner of credentialSource.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step3
        //spec| Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case),
        //spec| look up the corresponding credential public key.
        //      (This step is out of WebAuthn4J scope. It's caller's responsibility.)

        //spec| Step4
        //spec| Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData,
        //spec| and signature respectively.
        //      (This step is in createCoreAuthenticationObject method)

        //spec| Step5
        //spec| Let JSONtext be the result of running UTF-8 decode on the value of cData.
        //spec| Step6
        //spec| Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.

        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        CoreServerProperty serverProperty = authenticationParameters.getServerProperty();

        BeanAssertUtil.validate(authenticatorData);
        validateAuthenticatorData(authenticatorData);

        CoreAuthenticator authenticator = authenticationParameters.getAuthenticator();

        CoreAuthenticationObject authenticationObject = createCoreAuthenticationObject(authenticationData, authenticationParameters);

        //spec| Step11
        //spec| Verify that the rpIdHash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), serverProperty);

        //spec| Step12
        //spec| Verify that the User Present bit of the flags in authData is set.
        if (authenticationParameters.isUserPresenceRequired() && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Validator is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        //spec| Step13
        //spec| If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
        if (authenticationParameters.isUserVerificationRequired() && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Validator is configured to check user verified, but UV flag in authenticatorData is not set.");
        }

        //spec| Step14
        //spec| Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        //spec| extension outputs in the extensions in authData are as expected, considering the client extension input
        //spec| values that were given as the extensions option in the get() call. In particular, any extension identifier
        //spec| values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        //spec| identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        //spec| In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        authenticatorExtensionValidator.validate(authenticationExtensionsAuthenticatorOutputs);

        //spec| Using the credential public key, validate that sig is a valid signature over
        //spec| the binary concatenation of the authenticatorData and the hash of the collectedClientData.
        assertionSignatureValidator.validate(authenticationData, authenticator.getAttestedCredentialData().getCOSEKey());

        //spec| Step17
        //spec| If the signature counter value adata.signCount is nonzero or the value stored in conjunction with
        //spec| credential’s id attribute is nonzero, then run the following sub-step:
        long presentedCounter = authenticatorData.getSignCount();
        long storedCounter = authenticator.getCounter();
        if (presentedCounter > 0 || storedCounter > 0) {
            //spec| If the signature counter value adata.signCount is
            //spec| greater than the signature counter value stored in conjunction with credential’s id attribute.
            if (presentedCounter > storedCounter) {

                //spec| Update the stored signature counter value, associated with credential’s id attribute, to be the value of authData.signCount.

                //      (caller need to update the signature counter value based on the value set in the Authenticator instance)
                authenticator.setCounter(presentedCounter);
            }
            //spec| less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
            else {
                coreMaliciousCounterValueHandler.maliciousCounterValueDetected(authenticationObject);
            }
        }

        for (CustomCoreAuthenticationValidator customAuthenticationValidator : customAuthenticationValidators) {
            customAuthenticationValidator.validate(authenticationObject);
        }

        //spec| Step18
        //spec| If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.


    }

    protected @NonNull CoreAuthenticationObject createCoreAuthenticationObject(@NonNull CoreAuthenticationData authenticationData, @NonNull CoreAuthenticationParameters authenticationParameters) {
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

    void validateAuthenticatorData(@NonNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if (authenticatorData.getAttestedCredentialData() != null) {
            throw new ConstraintViolationException("attestedCredentialData must be null on authentication");
        }
    }

    public @NonNull CoreMaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return coreMaliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(@NonNull CoreMaliciousCounterValueHandler coreMaliciousCounterValueHandler) {
        AssertUtil.notNull(coreMaliciousCounterValueHandler, "maliciousCounterValueHandler must not be null");
        this.coreMaliciousCounterValueHandler = coreMaliciousCounterValueHandler;
    }

    public @NonNull List<CustomCoreAuthenticationValidator> getCustomAuthenticationValidators() {
        return customAuthenticationValidators;
    }
}
