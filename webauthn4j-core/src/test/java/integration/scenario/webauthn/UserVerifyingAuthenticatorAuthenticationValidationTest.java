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
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.*;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.validator.exception.*;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserVerifyingAuthenticatorAuthenticationValidationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final Origin origin = new Origin("http://example.com");
    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final WebAuthnManager target = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void validate_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );

        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensionResults = credential.getClientExtensionResults();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        clientExtensionJSON,
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        target.validate(authenticationData, authenticationParameters);

        assertAll(
                () -> assertThat(authenticationData.getCollectedClientData()).isNotNull(),
                () -> assertThat(authenticationData.getAuthenticatorData()).isNotNull(),
                () -> assertThat(authenticationData.getClientExtensions()).isNotNull()
        );
    }

    @Test
    void validate_assertion_with_tokenBinding_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );

        byte[] tokenBindingId = new byte[]{0x01, 0x23, 0x45};
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.GET, challenge, tokenBindingId);

        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions, collectedClientData);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensionResults = credential.getClientExtensionResults();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        clientExtensionJSON,
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        target.validate(authenticationData, authenticationParameters);

        assertAll(
                () -> assertThat(authenticationData.getCollectedClientData()).isNotNull(),
                () -> assertThat(authenticationData.getAuthenticatorData()).isNotNull(),
                () -> assertThat(authenticationData.getClientExtensions()).isNotNull()
        );
    }


    @Test
    void validate_assertion_test_with_bad_clientData_type() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.CREATE, challenge); // bad clientData type
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions, collectedClientData);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        assertThrows(InconsistentClientDataTypeException.class, () -> target.validate(authenticationData, authenticationParameters));
    }

    @Test
    void validate_assertion_with_bad_challenge_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();
        Challenge badChallenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                badChallenge, //bad challenge
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        assertThrows(BadChallengeException.class, () -> target.validate(authenticationData, authenticationParameters));
    }

    @Test
    void validate_assertion_with_bad_origin_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        clientPlatform.setOrigin(new Origin("https://bad.origin.example.com")); //bad origin
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);
        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        assertThrows(BadOriginException.class, () -> target.validate(authenticationData, authenticationParameters));
    }

    @Test
    void validate_assertion_with_invalid_tokenBinding_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );

        byte[] tokenBindingId = new byte[]{0x01, 0x23, 0x45};
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.GET, challenge, tokenBindingId);
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions, collectedClientData);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);
        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        assertThrows(TokenBindingException.class, () -> target.validate(authenticationData, authenticationParameters));
    }


    @Test
    void validate_bad_rpId_test() {
        String rpId = "example.com";
        String anotherSiteRpId = "another.site.example.net";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, anotherSiteRpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        assertThrows(BadRpIdException.class, () -> target.validate(authenticationData, authenticationParameters));

    }

    @Test
    void validate_assertion_with_userVerificationDiscouraged_option_test() {
        String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                null,
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);
        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );

        AuthenticationData authenticationData = target.parse(webAuthnAuthenticationRequest);
        assertThrows(UserNotVerifiedException.class, () -> target.validate(authenticationData, authenticationParameters));

    }


    private AttestationObject createAttestationObject(String rpId, Challenge challenge) {
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions
                = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                publicKeyCredentialUserEntity,
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.NONE,
                extensions
        );

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        return attestationObjectConverter.convert(registrationRequest.getAttestationObject());
    }
}
