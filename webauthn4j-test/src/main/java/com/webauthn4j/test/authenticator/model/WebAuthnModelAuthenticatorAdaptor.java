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

package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.request.PublicKeyCredentialCreationOptions;
import com.webauthn4j.request.PublicKeyCredentialRequestOptions;
import com.webauthn4j.request.UserVerificationRequirement;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.CredentialCreationResponse;
import com.webauthn4j.test.authenticator.CredentialRequestResponse;
import com.webauthn4j.test.client.AuthenticationEmulationOption;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;

public class WebAuthnModelAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private WebAuthnModelAuthenticator webAuthnModelAuthenticator = new WebAuthnModelAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(new Registry());

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData, RegistrationEmulationOption registrationEmulationOption) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        boolean requireUserVerification = getEffectiveUserVerificationRequirementForAssertion(publicKeyCredentialCreationOptions.getAuthenticatorSelection().getUserVerification());
        MakeCredentialRequest makeCredentialRequest = new MakeCredentialRequest();
        makeCredentialRequest.setHash(clientDataHash);
        makeCredentialRequest.setRpEntity(publicKeyCredentialCreationOptions.getRp());
        makeCredentialRequest.setUserEntity(publicKeyCredentialCreationOptions.getUser());
        makeCredentialRequest.setRequireResidentKey(publicKeyCredentialCreationOptions.getAuthenticatorSelection().isRequireResidentKey());
        makeCredentialRequest.setRequireUserPresence(true);
        makeCredentialRequest.setRequireUserVerification(requireUserVerification);
        makeCredentialRequest.setCredTypesAndPublicKeyAlgs(publicKeyCredentialCreationOptions.getPubKeyCredParams());
        makeCredentialRequest.setExcludeCredentialDescriptorList(publicKeyCredentialCreationOptions.getExcludeCredentials());
        makeCredentialRequest.setExtensions(publicKeyCredentialCreationOptions.getExtensions());
        MakeCredentialResponse makeCredentialResponse = webAuthnModelAuthenticator.makeCredential(makeCredentialRequest, registrationEmulationOption);

        return new CredentialCreationResponse(makeCredentialResponse.getAttestationObject());
    }

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData) {
        return register(publicKeyCredentialCreationOptions, collectedClientData, new RegistrationEmulationOption());
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

        GetAssertionRequest getAssertionRequest = new GetAssertionRequest();
        getAssertionRequest.setRpId(publicKeyCredentialRequestOptions.getRpId());
        getAssertionRequest.setHash(clientDataHash);
        getAssertionRequest.setAllowCredentialDescriptorList(publicKeyCredentialRequestOptions.getAllowCredentials());
        getAssertionRequest.setRequireUserPresence(true);
        getAssertionRequest.setRequireUserVerification(requireUserVerification);
        getAssertionRequest.setExtensions(publicKeyCredentialRequestOptions.getExtensions());

        GetAssertionResponse getAssertionResponse = webAuthnModelAuthenticator.getAssertion(getAssertionRequest, authenticationEmulationOption);

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
                return webAuthnModelAuthenticator.isCapableOfUserVerification();
            case DISCOURAGED:
                return false;
            default:
                throw new NotImplementedException();
        }
    }
}
