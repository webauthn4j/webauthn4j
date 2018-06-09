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

package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.authenticator.ECCredentialPublicKey;
import com.webauthn4j.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.CredentialCreationResponse;
import com.webauthn4j.test.authenticator.CredentialRequestResponse;
import com.webauthn4j.test.client.*;
import com.webauthn4j.util.MessageDigestUtil;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;

public class FIDOU2FAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private FIDOU2FAuthenticator fidoU2FAuthenticator = new FIDOU2FAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter();

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData, RegistrationEmulationOption registrationEmulationOption) {
        String rpId = publicKeyCredentialCreationOptions.getRp().getId();
        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.getBytes(StandardCharsets.UTF_8));

        byte[] challengeParameter = MessageDigestUtil.createSHA256().digest(collectedClientDataConverter.convertToBytes(collectedClientData));
        //noinspection UnnecessaryLocalVariable
        byte[] applicationParameter = rpIdHash;
        RegistrationRequest registrationRequest = new RegistrationRequest(challengeParameter, applicationParameter);
        RegistrationResponse registrationResponse = fidoU2FAuthenticator.register(registrationRequest, registrationEmulationOption);

        AttestationStatement attestationStatement = new FIDOU2FAttestationStatement(
                new AttestationCertificatePath(Collections.singletonList(registrationResponse.getAttestationCertificate())),
                registrationResponse.getSignature()
        );

        ECCredentialPublicKey ecCredentialPublicKey = ECCredentialPublicKey.createFromUncompressedECCKey(registrationResponse.getUserPublicKey());

        byte[] aaGuid = new byte[16]; // zero-filled 16bytes(128bits) array
        AttestedCredentialData attestedCredentialData =
                new AttestedCredentialData(aaGuid, registrationResponse.getKeyHandle(), ecCredentialPublicKey);

        byte flag = BIT_AT | BIT_UP;
        AuthenticatorData authenticatorData = new AuthenticatorData(rpIdHash, flag, 0, attestedCredentialData);

        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);

        return new CredentialCreationResponse(attestationObject);
    }

    @Override
    public CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                               CollectedClientData collectedClientData) {
        return register(publicKeyCredentialCreationOptions, collectedClientData, new RegistrationEmulationOption());
    }

    @Override
    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                                  CollectedClientData collectedClientData,
                                                  AuthenticationEmulationOption authenticationEmulationOption) {
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        String rpId = publicKeyCredentialRequestOptions.getRpId();

        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.getBytes(StandardCharsets.UTF_8));
        byte control = 0x00;
        byte[] challenge = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        //noinspection UnnecessaryLocalVariable
        byte[] applicationParameter = rpIdHash;

        List<PublicKeyCredentialDescriptor> publicKeyCredentialDescriptors = publicKeyCredentialRequestOptions.getAllowCredentials();

        PublicKeyCredentialDescriptor publicKeyCredentialDescriptor = publicKeyCredentialDescriptors.get(0);
        //TODO: what to do if multiple publicKeyCredentialDescriptors are supplied

        byte[] keyHandle = publicKeyCredentialDescriptor.getId();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(control, challenge, applicationParameter, keyHandle);

        AuthenticationResponse authenticationResponse = fidoU2FAuthenticator.authenticate(authenticationRequest, authenticationEmulationOption);

        byte[] credentialId = publicKeyCredentialDescriptor.getId();
        long counter = ByteBuffer.allocate(8).put(new byte[4]).put(authenticationResponse.getCounter()).getLong(0);
        AuthenticatorData authenticatorData = new AuthenticatorData(rpIdHash, authenticationResponse.getUserPresense(), counter);

        byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
        byte[] signature = authenticationResponse.getSignature();
        return new CredentialRequestResponse(credentialId, collectedClientDataBytes, authenticatorDataBytes, signature, null);
    }

    @Override
    public CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                                  CollectedClientData collectedClientData) {
        return authenticate(publicKeyCredentialRequestOptions, collectedClientData, new AuthenticationEmulationOption());
    }

    public FIDOU2FAuthenticator getFidoU2FAuthenticator() {
        return fidoU2FAuthenticator;
    }
}
