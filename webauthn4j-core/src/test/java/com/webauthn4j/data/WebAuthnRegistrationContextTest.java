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

package com.webauthn4j.data;

import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestConstants;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class WebAuthnRegistrationContextTest {

    private JsonConverter jsonConverter = new JsonConverter();


    private Origin origin = new Origin("http://localhost");
    private WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(TestConstants.PACKED_AUTHENTICATOR);
    private ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

    private AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(jsonConverter);

    @Test
    void constructor_test(){
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
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
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
        AuthenticatorAttestationResponse registrationRequest = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs clientExtensionResults = credential.getClientExtensionResults();
        Set<String> transports = Collections.emptySet();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext instanceA = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                transports,
                clientExtensionJSON,
                serverProperty,
                true,
                true,
                Collections.emptyList()
        );

        assertAll(
                ()-> assertThat(instanceA.getClientDataJSON()).isEqualTo(registrationRequest.getClientDataJSON()),
                ()-> assertThat(instanceA.getAttestationObject()).isEqualTo(registrationRequest.getAttestationObject()),
                ()-> assertThat(instanceA.getTransports()).isEqualTo(transports),
                ()-> assertThat(instanceA.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON),
                ()-> assertThat(instanceA.getServerProperty()).isEqualTo(serverProperty),
                ()-> assertThat(instanceA.isUserPresenceRequired()).isEqualTo(true),
                ()-> assertThat(instanceA.isUserVerificationRequired()).isEqualTo(true),
                ()-> assertThat(instanceA.getExpectedExtensionIds()).isEqualTo(Collections.emptyList())
        );

        WebAuthnRegistrationContext instanceB = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                transports,
                clientExtensionJSON,
                serverProperty,
                true,
                Collections.emptyList()
        );

        assertAll(
                ()-> assertThat(instanceB.getClientDataJSON()).isEqualTo(registrationRequest.getClientDataJSON()),
                ()-> assertThat(instanceB.getAttestationObject()).isEqualTo(registrationRequest.getAttestationObject()),
                ()-> assertThat(instanceB.getTransports()).isEqualTo(transports),
                ()-> assertThat(instanceB.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON),
                ()-> assertThat(instanceB.getServerProperty()).isEqualTo(serverProperty),
                ()-> assertThat(instanceB.isUserPresenceRequired()).isEqualTo(true),
                ()-> assertThat(instanceB.isUserVerificationRequired()).isEqualTo(true),
                ()-> assertThat(instanceB.getExpectedExtensionIds()).isEqualTo(Collections.emptyList())
        );

        WebAuthnRegistrationContext instanceC = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                transports,
                serverProperty,
                true
        );

        assertAll(
                ()-> assertThat(instanceC.getClientDataJSON()).isEqualTo(registrationRequest.getClientDataJSON()),
                ()-> assertThat(instanceC.getAttestationObject()).isEqualTo(registrationRequest.getAttestationObject()),
                ()-> assertThat(instanceC.getTransports()).isEqualTo(transports),
                ()-> assertThat(instanceC.getClientExtensionsJSON()).isNull(),
                ()-> assertThat(instanceC.getServerProperty()).isEqualTo(serverProperty),
                ()-> assertThat(instanceC.isUserPresenceRequired()).isEqualTo(true),
                ()-> assertThat(instanceC.isUserVerificationRequired()).isEqualTo(true),
                ()-> assertThat(instanceC.getExpectedExtensionIds()).isEqualTo(Collections.emptyList())
        );

        WebAuthnRegistrationContext instanceD = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                clientExtensionJSON,
                serverProperty,
                true,
                Collections.emptyList()
        );

        assertAll(
                ()-> assertThat(instanceD.getClientDataJSON()).isEqualTo(registrationRequest.getClientDataJSON()),
                ()-> assertThat(instanceD.getAttestationObject()).isEqualTo(registrationRequest.getAttestationObject()),
                ()-> assertThat(instanceD.getTransports()).isEqualTo(Collections.emptySet()),
                ()-> assertThat(instanceD.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON),
                ()-> assertThat(instanceD.getServerProperty()).isEqualTo(serverProperty),
                ()-> assertThat(instanceD.isUserPresenceRequired()).isEqualTo(true),
                ()-> assertThat(instanceD.isUserVerificationRequired()).isEqualTo(true),
                ()-> assertThat(instanceD.getExpectedExtensionIds()).isEqualTo(Collections.emptyList())
        );

        WebAuthnRegistrationContext instanceE = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                clientExtensionJSON,
                serverProperty,
                true,
                true,
                Collections.emptyList()
        );

        assertAll(
                ()-> assertThat(instanceE.getClientDataJSON()).isEqualTo(registrationRequest.getClientDataJSON()),
                ()-> assertThat(instanceE.getAttestationObject()).isEqualTo(registrationRequest.getAttestationObject()),
                ()-> assertThat(instanceE.getTransports()).isEqualTo(Collections.emptySet()),
                ()-> assertThat(instanceE.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON),
                ()-> assertThat(instanceE.getServerProperty()).isEqualTo(serverProperty),
                ()-> assertThat(instanceE.isUserPresenceRequired()).isEqualTo(true),
                ()-> assertThat(instanceE.isUserVerificationRequired()).isEqualTo(true),
                ()-> assertThat(instanceE.getExpectedExtensionIds()).isEqualTo(Collections.emptyList())
        );

        WebAuthnRegistrationContext instanceF = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                serverProperty,
                true
        );

        assertAll(
                ()-> assertThat(instanceF.getClientDataJSON()).isEqualTo(registrationRequest.getClientDataJSON()),
                ()-> assertThat(instanceF.getAttestationObject()).isEqualTo(registrationRequest.getAttestationObject()),
                ()-> assertThat(instanceF.getTransports()).isEqualTo(Collections.emptySet()),
                ()-> assertThat(instanceF.getClientExtensionsJSON()).isNull(),
                ()-> assertThat(instanceF.getServerProperty()).isEqualTo(serverProperty),
                ()-> assertThat(instanceF.isUserPresenceRequired()).isEqualTo(true),
                ()-> assertThat(instanceF.isUserVerificationRequired()).isEqualTo(true),
                ()-> assertThat(instanceF.getExpectedExtensionIds()).isEqualTo(Collections.emptyList())
        );


    }

}