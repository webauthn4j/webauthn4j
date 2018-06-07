package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.extension.ExtensionIdentifier;
import com.webauthn4j.test.authenticator.*;
import com.webauthn4j.test.client.*;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class WebAuthnModelAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private WebAuthnModelAuthenticator webAuthnModelAuthenticator = new WebAuthnModelAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData, RegistrationEmulationOption registrationEmulationOption) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        boolean requireUserVerification = getEffectiveUserVerificationRequirementForAssertion(publicKeyCredentialCreationOptions.getAuthenticatorSelection().getUserVerificationRequirement());
        MakeCredentialRequest makeCredentialRequest = new MakeCredentialRequest();
        makeCredentialRequest.setHash(clientDataHash);
        makeCredentialRequest.setRpEntity(publicKeyCredentialCreationOptions.getRp());
        makeCredentialRequest.setUserEntity(publicKeyCredentialCreationOptions.getUser());
        makeCredentialRequest.setRequireResidentKey(publicKeyCredentialCreationOptions.getAuthenticatorSelection().isRequireResidentKey());
        makeCredentialRequest.setRequireUserPresence(!requireUserVerification);
        makeCredentialRequest.setRequireUserVerification(requireUserVerification);
        makeCredentialRequest.setCredTypesAndPublicKeyAlgs(publicKeyCredentialCreationOptions.getPubKeyCredParams());
        makeCredentialRequest.setExcludeCredentialDescriptorList(publicKeyCredentialCreationOptions.getExcludeCredentials());
        makeCredentialRequest.setExtensions(convertExtensions(publicKeyCredentialCreationOptions.getExtensions()));
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
        getAssertionRequest.setRequireUserPresence(!requireUserVerification);
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

    private Map<ExtensionIdentifier,AuthenticatorExtensionInput> convertExtensions(Map<ExtensionIdentifier,ClientExtensionInput> extensions) {
        if(extensions == null){
            return Collections.emptyMap();
        }

        Map<ExtensionIdentifier, AuthenticatorExtensionInput> map = new HashMap<>();
        for(Map.Entry<ExtensionIdentifier, ClientExtensionInput> clientExtensionInputEntry : extensions.entrySet()){
            ExtensionIdentifier extensionIdentifier = clientExtensionInputEntry.getKey();
            if(extensionIdentifier.equals(SupportedExtensionsClientExtensionInput.ID)){
                SupportedExtensionsClientExtensionInput clientExtensionInput = (SupportedExtensionsClientExtensionInput) clientExtensionInputEntry.getValue();
                map.put(SupportedExtensionsClientExtensionInput.ID, new SupportedExtensionsAuthenticatorExtensionInput(clientExtensionInput.getValue()));
            }
        }
        return map;
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
