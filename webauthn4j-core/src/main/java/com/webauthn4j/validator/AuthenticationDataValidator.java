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
import com.webauthn4j.validator.exception.ConstraintViolationException;
import com.webauthn4j.validator.exception.InconsistentClientDataTypeException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AuthenticationDataValidator {

    private final ChallengeValidator challengeValidator = new ChallengeValidator();
    private final OriginValidator originValidator = new OriginValidator();
    private final TokenBindingValidator tokenBindingValidator = new TokenBindingValidator();
    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private final AssertionSignatureValidator assertionSignatureValidator = new AssertionSignatureValidator();
    private final ClientExtensionValidator clientExtensionValidator = new ClientExtensionValidator();
    private final AuthenticatorExtensionValidator authenticatorExtensionValidator = new AuthenticatorExtensionValidator();

    private final List<CustomAuthenticationValidator> customAuthenticationValidators;

    private CoreMaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultCoreMaliciousCounterValueHandler();

    public AuthenticationDataValidator(@NonNull List<CustomAuthenticationValidator> customAuthenticationValidators) {
        this.customAuthenticationValidators = customAuthenticationValidators;
    }

    public AuthenticationDataValidator() {
        this.customAuthenticationValidators = new ArrayList<>();
    }

    @SuppressWarnings("ConstantConditions") // as null check is done by BeanAssertUtil#validate
    public void validate(@NonNull AuthenticationData authenticationData, @NonNull AuthenticationParameters authenticationParameters) {

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
        byte[] cData = authenticationData.getCollectedClientDataBytes();
        byte[] aData = authenticationData.getAuthenticatorDataBytes();

        //spec| Step5
        //spec| Let JSONtext be the result of running UTF-8 decode on the value of cData.
        //spec| Step6
        //spec| Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.

        //      (In the spec, claimed as "C", but use "collectedClientData" here)
        CollectedClientData collectedClientData = authenticationData.getCollectedClientData();

        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions = authenticationData.getClientExtensions();
        ServerProperty serverProperty = authenticationParameters.getServerProperty();

        BeanAssertUtil.validate(collectedClientData);
        BeanAssertUtil.validate(authenticatorData);

        validateAuthenticatorData(authenticatorData);

        byte[] credentialId = authenticationData.getCredentialId();
        Authenticator authenticator = authenticationParameters.getAuthenticator();

        AuthenticationObject authenticationObject = new AuthenticationObject(
                credentialId, authenticatorData, aData, collectedClientData, cData, clientExtensions,
                serverProperty, authenticator
        );

        //spec| Step7
        //spec| Verify that the value of C.type is the string webauthn.get.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.GET)) {
            throw new InconsistentClientDataTypeException("ClientData.type must be 'get' on authentication, but it isn't.");
        }

        //spec| Step8
        //spec| Verify that the value of C.challenge matches the challenge that was sent to the authenticator in
        //spec| the PublicKeyCredentialRequestOptions passed to the get() call.
        challengeValidator.validate(collectedClientData, serverProperty);

        //spec| Step9
        //spec| Verify that the value of C.origin matches the Relying Party's origin.
        originValidator.validate(collectedClientData, serverProperty);

        //spec| Step10
        //spec| Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        //spec| which the attestation was obtained. If Token Binding was used on that TLS connection,
        //spec| also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        tokenBindingValidator.validate(collectedClientData.getTokenBinding(), serverProperty.getTokenBindingId());

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
        clientExtensionValidator.validate(clientExtensions);
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
                maliciousCounterValueHandler.maliciousCounterValueDetected(authenticationObject);
            }
        }

        for (CustomAuthenticationValidator customAuthenticationValidator : customAuthenticationValidators) {
            customAuthenticationValidator.validate(authenticationObject);
        }

        //spec| Step18
        //spec| If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.


    }

    void validateAuthenticatorData(@NonNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        if (authenticatorData.getAttestedCredentialData() != null) {
            throw new ConstraintViolationException("attestedCredentialData must be null on authentication");
        }
    }

    public @NonNull CoreMaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return maliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(@NonNull CoreMaliciousCounterValueHandler maliciousCounterValueHandler) {
        AssertUtil.notNull(maliciousCounterValueHandler, "maliciousCounterValueHandler must not be null");
        this.maliciousCounterValueHandler = maliciousCounterValueHandler;
    }

    public @NonNull List<CustomAuthenticationValidator> getCustomAuthenticationValidators() {
        return customAuthenticationValidators;
    }
}
