package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.authenticator.ESCredentialPublicKey;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.CredentialCreationResponse;
import com.webauthn4j.test.authenticator.CredentialRequestResponse;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.MessageDigestUtil;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;

public class FIDOU2FAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private FIDOU2FAuthenticator fidoU2FAuthenticator = new FIDOU2FAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter();

    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData, RegistrationEmulationOption registrationEmulationOption) {
        String rpId = publicKeyCredentialCreationOptions.getRp().getId();
        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.getBytes(StandardCharsets.UTF_8));

        byte[] challengeParameter = MessageDigestUtil.createSHA256().digest(collectedClientDataConverter.convertToBytes(collectedClientData));
        byte[] applicationParameter = rpIdHash;
        RegistrationRequest registrationRequest = new RegistrationRequest(challengeParameter, applicationParameter);
        RegistrationResponse registrationResponse = fidoU2FAuthenticator.register(registrationRequest, registrationEmulationOption);

        AttestationStatement attestationStatement = new FIDOU2FAttestationStatement(
                CertificateUtil.generateCertPath(Collections.singletonList(registrationResponse.getAttestationCertificate())),
                registrationResponse.getSignature()
        );

        ESCredentialPublicKey esCredentialPublicKey = ESCredentialPublicKey.create(registrationResponse.getUserPublicKey());

        byte[] aaGuid = new byte[16]; // zero-filled 16bytes(128bits) array
        AttestedCredentialData attestedCredentialData =
                new AttestedCredentialData(aaGuid, registrationResponse.getKeyHandle(), esCredentialPublicKey);

        byte flag = BIT_AT | BIT_UP;
        AuthenticatorData authenticatorData = new AuthenticatorData(rpIdHash, flag, 0, attestedCredentialData, null);

        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);

        return new CredentialCreationResponse(attestationObject);
    }

    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                               CollectedClientData collectedClientData) {
        return register(publicKeyCredentialCreationOptions, collectedClientData, new RegistrationEmulationOption());
    }

    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                                  CollectedClientData collectedClientData,
                                                  PublicKeyCredentialDescriptor credentialDescriptor,
                                                  AuthenticationEmulationOption authenticationEmulationOption) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        String rpId = publicKeyCredentialRequestOptions.getRpId();

        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.getBytes(StandardCharsets.UTF_8));
        byte control = 0x00;
        byte[] challenge = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        byte[] applicationParameter = rpIdHash;
        byte[] keyHandle = credentialDescriptor.getId();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(control, challenge, applicationParameter, keyHandle);

        AuthenticationResponse authenticationResponse = fidoU2FAuthenticator.authenticate(authenticationRequest, authenticationEmulationOption);

        byte[] credentialId = credentialDescriptor.getId();
        long counter = ByteBuffer.allocate(8).put(new byte[4]).put(authenticationResponse.getCounter()).getLong(0);
        AuthenticatorData authenticatorData = new AuthenticatorData(rpIdHash, authenticationResponse.getUserPresense(), counter, null, null);

        byte[] authenticatorDataBytes = authenticatorDataConverter.convertToBytes(authenticatorData);
        byte[] signature = authenticationResponse.getSignature();
        return new CredentialRequestResponse(credentialId, collectedClientDataBytes, authenticatorDataBytes, signature, null);
    }

    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                                  CollectedClientData collectedClientData,
                                                  PublicKeyCredentialDescriptor credentialDescriptor){
        return authenticate(publicKeyCredentialRequestOptions, collectedClientData, credentialDescriptor, new AuthenticationEmulationOption());
    }

    public FIDOU2FAuthenticator getFidoU2FAuthenticator() {
        return fidoU2FAuthenticator;
    }
}
