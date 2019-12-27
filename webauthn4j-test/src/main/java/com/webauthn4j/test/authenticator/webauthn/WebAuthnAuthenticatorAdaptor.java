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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.CredentialCreationResponse;
import com.webauthn4j.test.authenticator.CredentialRequestResponse;
import com.webauthn4j.test.client.AuthenticationEmulationOption;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;

public class WebAuthnAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private WebAuthnAuthenticator webAuthnAuthenticator;
    private CollectedClientDataConverter collectedClientDataConverter;

    public WebAuthnAuthenticatorAdaptor(WebAuthnAuthenticator webAuthnAuthenticator, ObjectConverter objectConverter) {
        this.webAuthnAuthenticator = webAuthnAuthenticator;
        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
    }

    public WebAuthnAuthenticatorAdaptor(WebAuthnAuthenticator webAuthnAuthenticator) {
        this(webAuthnAuthenticator, new ObjectConverter());
    }

    @Override
    public CredentialCreationResponse register(
            PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
            CollectedClientData collectedClientData,
            RegistrationEmulationOption registrationEmulationOption,
            AttestationOption attestationOption
    ) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        boolean requireUserVerification = getEffectiveUserVerificationRequirementForAssertion(publicKeyCredentialCreationOptions.getAuthenticatorSelection().getUserVerification());
        MakeCredentialRequest makeCredentialRequest = new MakeCredentialRequest(
                clientDataHash,
                publicKeyCredentialCreationOptions.getRp(),
                publicKeyCredentialCreationOptions.getUser(),
                publicKeyCredentialCreationOptions.getAuthenticatorSelection().isRequireResidentKey(),
                true,
                requireUserVerification,
                publicKeyCredentialCreationOptions.getPubKeyCredParams(),
                publicKeyCredentialCreationOptions.getExcludeCredentials(),
                publicKeyCredentialCreationOptions.getExtensions()
        );
        MakeCredentialResponse makeCredentialResponse = webAuthnAuthenticator.makeCredential(makeCredentialRequest, registrationEmulationOption);

        return new CredentialCreationResponse(makeCredentialResponse.getAttestationObject());
    }

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData) {
        return register(publicKeyCredentialCreationOptions, collectedClientData, new RegistrationEmulationOption(), null);
    }

    @Override
    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData) {
        return authenticate(publicKeyCredentialRequestOptions, collectedClientData, new AuthenticationEmulationOption());
    }

    @Override
    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData,
                                                  AuthenticationEmulationOption authenticationEmulationOption) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        boolean requireUserVerification = getEffectiveUserVerificationRequirementForAssertion(publicKeyCredentialRequestOptions.getUserVerification());

        GetAssertionRequest getAssertionRequest = new GetAssertionRequest(
                publicKeyCredentialRequestOptions.getRpId(),
                clientDataHash,
                publicKeyCredentialRequestOptions.getAllowCredentials(),
                true,
                requireUserVerification,
                publicKeyCredentialRequestOptions.getExtensions()
        );

        GetAssertionResponse getAssertionResponse = webAuthnAuthenticator.getAssertion(getAssertionRequest, authenticationEmulationOption);

        return new CredentialRequestResponse(
                getAssertionResponse.getCredentialId(),
                collectedClientDataBytes,
                getAssertionResponse.getAuthenticatorData(),
                getAssertionResponse.getSignature(),
                getAssertionResponse.getUserHandle()
        );
    }

    private boolean getEffectiveUserVerificationRequirementForAssertion(UserVerificationRequirement userVerificationRequirement) {
        switch (userVerificationRequirement) {
            case REQUIRED:
                return true;
            case PREFERRED:
                return webAuthnAuthenticator.isCapableOfUserVerification();
            case DISCOURAGED:
                return false;
            default:
                throw new NotImplementedException();
        }
    }
}
