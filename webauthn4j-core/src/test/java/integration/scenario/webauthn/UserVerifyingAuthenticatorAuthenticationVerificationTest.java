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

package integration.scenario.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.verifier.exception.*;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings("ConstantConditions")
class UserVerifyingAuthenticatorAuthenticationVerificationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);

    private final Origin origin = new Origin("http://example.com");
    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final WebAuthnManager target = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void should_success() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatCode(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_token_binding_is_provided() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        byte[] tokenBindingId = new byte[]{0x01, 0x23, 0x45};

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_GET, challenge, tokenBindingId);
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatCode(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).doesNotThrowAnyException();

    }


    @Test
    void should_throw_when_invalid_ClientDataType_is_not_provided() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_CREATE, challenge); // bad clientData type
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(InconsistentClientDataTypeException.class);
    }

    @Test
    void should_throw_when_invalid_challenge_is_provided() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        Challenge badChallenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_GET, badChallenge); // bad challenge
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(BadChallengeException.class);
    }

    @Test
    void should_throw_when_invalid_origin_is_provided() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        clientPlatform.setOrigin(new Origin("https://bad.origin.example.com")); //bad origin
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_GET, challenge);
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(BadOriginException.class);
    }

    @Test
    void should_throw_when_invalid_tokenBinding_is_provided() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        byte[] tokenBindingId = new byte[]{0x01, 0x23, 0x45};

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_GET, challenge, tokenBindingId);
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(TokenBindingException.class);
    }


    @Test
    void should_throw_when_invalid_rpId_is_provided() {
        String rpId = "example.com";
        String anotherSiteRpId = "another.site.example.net";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_GET, challenge, null);
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, anotherSiteRpId, challenge, null); // invalid rpId

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(BadRpIdException.class);
    }

    @Test
    void should_throw_when_uv_false_with_userVerificationRequired_true_option() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.DISCOURAGED, //discourage UV
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.WEBAUTHN_GET, challenge, null);
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->target.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(UserNotVerifiedException.class);
    }

    private CredentialRecord createCredentialRecord(String rpId, Challenge challenge) {

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<>()
        );

        var response = clientPlatform.create(credentialCreationOptions);
        var registrationRequest = response.getResponse();
        AttestationObject attestationObject = attestationObjectConverter.convert(registrationRequest.getAttestationObject());
        var clientData = collectedClientDataConverter.convert(registrationRequest.getClientDataJSON());
        return new CredentialRecordImpl(attestationObject, clientData, response.getClientExtensionResults(), registrationRequest.getTransports());
    }
}
