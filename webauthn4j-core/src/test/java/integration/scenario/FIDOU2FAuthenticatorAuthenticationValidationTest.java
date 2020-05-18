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

package integration.scenario;

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
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticator;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.CollectionUtil;
import com.webauthn4j.validator.exception.*;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FIDOU2FAuthenticatorAuthenticationValidationTest {

    private ObjectConverter objectConverter = new ObjectConverter();

    private Origin origin = new Origin("http://example.com");
    private ClientPlatform clientPlatform = new ClientPlatform(origin, new FIDOU2FAuthenticatorAdaptor());
    private WebAuthnManager target = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

    private AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticationRequest = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput<?>> clientExtensionResults = credential.getClientExtensionResults();
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
        AuthenticationParameters webAuthnAuthenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false,
                        true,
                        Collections.emptyList()
                );

        AuthenticationData response = target.validate(webAuthnAuthenticationRequest, webAuthnAuthenticationParameters);

        assertAll(
                () -> assertThat(response.getCollectedClientData()).isNotNull(),
                () -> assertThat(response.getAuthenticatorData()).isNotNull(),
                () -> assertThat(response.getClientExtensions()).isNotNull()
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.CREATE, challenge); // bad clientData type
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> publicKeyCredential = clientPlatform.get(credentialRequestOptions, collectedClientData);
        AuthenticatorAssertionResponse authenticationRequest = publicKeyCredential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest webAuthnAuthenticationRequest =
                new AuthenticationRequest(
                        publicKeyCredential.getRawId(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getClientDataJSON(),
                        authenticationRequest.getSignature()
                );
        AuthenticationParameters webAuthnAuthenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false
                );

        assertThrows(InconsistentClientDataTypeException.class,
                () -> target.validate(webAuthnAuthenticationRequest, webAuthnAuthenticationParameters)
        );
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
                badChallenge, // bad challenge
                timeout,
                rpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
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
        AuthenticationParameters webAuthnAuthenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false
                );

        assertThrows(BadChallengeException.class,
                () -> target.validate(webAuthnAuthenticationRequest, webAuthnAuthenticationParameters)
        );
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        clientPlatform.setOrigin(new Origin("https://bad.origin.example.com")); //bad origin
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticatorAssertionResponse.getAuthenticatorData(),
                        authenticatorAssertionResponse.getClientDataJSON(),
                        authenticatorAssertionResponse.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false
                );

        assertThrows(BadOriginException.class,
                () -> target.validate(authenticationRequest, authenticationParameters)
        );
    }

    @Test
    void validate_assertion_with_bad_rpId_test() {
        String rpId = "example.com";
        String badRpId = "bad.rpId.example.net";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        AttestationObject attestationObject = createAttestationObject(rpId, challenge);

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                badRpId,
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticatorAssertionResponse.getAuthenticatorData(),
                        authenticatorAssertionResponse.getClientDataJSON(),
                        authenticatorAssertionResponse.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false
                );
        assertThrows(BadRpIdException.class,
                () -> target.validate(authenticationRequest, authenticationParameters)
        );
    }

    @Test
    void validate_assertion_with_userVerificationRequired_option_test() {
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticatorAssertionResponse.getAuthenticatorData(),
                        authenticatorAssertionResponse.getClientDataJSON(),
                        authenticatorAssertionResponse.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        true
                );
        assertThrows(UserNotVerifiedException.class,
                () -> target.validate(authenticationRequest, authenticationParameters)
        );
    }

    @Test
    void validate_assertion_with_UP_flag_off_test() {
        FIDOU2FAuthenticatorAdaptor fidou2FAuthenticatorAdaptor = new FIDOU2FAuthenticatorAdaptor();
        fidou2FAuthenticatorAdaptor.getFIDOU2FAuthenticator().setFlags(FIDOU2FAuthenticator.FLAG_OFF);
        clientPlatform = new ClientPlatform(origin, fidou2FAuthenticatorAdaptor);
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticatorAssertionResponse.getAuthenticatorData(),
                        authenticatorAssertionResponse.getClientDataJSON(),
                        authenticatorAssertionResponse.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false,
                        true
                );
        assertThrows(UserNotPresentException.class,
                () -> target.validate(authenticationRequest, authenticationParameters)
        );
    }

    @Test
    void validate_assertion_with_bad_signature_test() {
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticatorAssertionResponse.getAuthenticatorData(),
                        authenticatorAssertionResponse.getClientDataJSON(),
                        new byte[32] //bad signature
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false,
                        true
                );
        assertThrows(BadSignatureException.class,
                () -> target.validate(authenticationRequest, authenticationParameters)
        );
    }

    @Test
    void validate_assertion_with_malicious_counter_test() {
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
                Collections.singletonList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput<?>> credential = clientPlatform.get(credentialRequestOptions);
        AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);
        authenticator.setCounter(100); //set expected minimum counter bigger than that of actual authenticator

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credential.getRawId(),
                        authenticatorAssertionResponse.getAuthenticatorData(),
                        authenticatorAssertionResponse.getClientDataJSON(),
                        authenticatorAssertionResponse.getSignature()
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        false,
                        true
                );
        assertThrows(MaliciousCounterValueException.class,
                () -> target.validate(authenticationRequest, authenticationParameters)
        );
    }

    private AttestationObject createAttestationObject(String rpId, Challenge challenge) {
        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );
        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        return attestationObjectConverter.convert(registrationRequest.getAttestationObject());
    }
}
