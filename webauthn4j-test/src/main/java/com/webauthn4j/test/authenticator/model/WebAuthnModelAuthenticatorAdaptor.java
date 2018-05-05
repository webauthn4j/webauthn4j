package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.test.authenticator.CredentialRequestResponse;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.CredentialCreationResponse;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;

public class WebAuthnModelAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private WebAuthnModelAuthenticator webAuthnModelAuthenticator = new WebAuthnModelAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData, RegistrationEmulationOption registrationEmulationOption) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        boolean requireUserVerification;
        switch (publicKeyCredentialCreationOptions.getAuthenticatorSelection().getUserVerificationRequirement()){
            case REQUIRED:
                requireUserVerification = true;
                break;
            case PREFERRED:
                requireUserVerification = webAuthnModelAuthenticator.isCapableOfUserVerification();
                break;
            case DISCOURAGED:
                requireUserVerification = false;
                break;
            default:
                throw new NotImplementedException();
        }
        MakeCredentialRequest makeCredentialRequest = new MakeCredentialRequest();
        makeCredentialRequest.setHash(clientDataHash);
        makeCredentialRequest.setRpEntity(publicKeyCredentialCreationOptions.getRp());
        makeCredentialRequest.setUserEntity(publicKeyCredentialCreationOptions.getUser());
        makeCredentialRequest.setRequireResidentKey(publicKeyCredentialCreationOptions.getAuthenticatorSelection().isRequireResidentKey());
        makeCredentialRequest.setRequireUserPresence(!requireUserVerification);
        makeCredentialRequest.setRequireUserVerification(requireUserVerification);
        makeCredentialRequest.setCredTypesAndPublicKeyAlgs(publicKeyCredentialCreationOptions.getPubKeyCredParams());
        makeCredentialRequest.setExcludeCredentialDescriptorList(publicKeyCredentialCreationOptions.getExcludeCredentials());
        makeCredentialRequest.setExtensions(publicKeyCredentialCreationOptions.getExtentions());
        MakeCredentialResponse makeCredentialResponse = webAuthnModelAuthenticator.makeCredential(makeCredentialRequest, registrationEmulationOption);

        /*
        AttestationStatement attestationStatement;

        ESCredentialPublicKey esCredentialPublicKey = convertToEsCredentialPublicKey(makeCredentialResponse.getUserPublicKey());

        byte[] aaGuid = new byte[16]; // zero-filled 16bytes(128bits) array
        AttestedCredentialData attestedCredentialData =
                new AttestedCredentialData(aaGuid, makeCredentialResponse.getKeyHandle(), esCredentialPublicKey);

        byte flag = BIT_AT | BIT_UP;
        AuthenticatorData authenticatorData = new AuthenticatorData();


        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);

        byte[] attestationObjectBytes = attestationObjectConverter.convertToBytes(attestationObject);
        */

        return new CredentialCreationResponse(makeCredentialResponse.getAttestationObject());
    }

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData) {
        return register(publicKeyCredentialCreationOptions, collectedClientData, new RegistrationEmulationOption());
    }

    @Override
    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData, PublicKeyCredentialDescriptor credentialDescriptor) {
        return null;
    }

    @Override
    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData, PublicKeyCredentialDescriptor credentialDescriptor, AuthenticationEmulationOption authenticationEmulationOption) {
        return null;
    }
}
