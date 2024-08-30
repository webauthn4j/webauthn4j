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
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.ClientPlatform;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;

@SuppressWarnings("ConstantConditions")
class AuthenticationResponseJSONVerificationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final Origin origin = new Origin("http://example.com");
    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final WebAuthnManager target = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);


    @Test
    void test() {
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
        String authenticationResponseJSON = objectConverter.getJsonConverter().writeValueAsString(credential);


        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestationObject);

        List<byte[]> allowCredentials = null;
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        allowCredentials,
                        true
                );

        assertThatCode(()->target.parseAuthenticationResponseJSON(authenticationResponseJSON)).doesNotThrowAnyException();
        AuthenticationData authenticationData = target.parseAuthenticationResponseJSON(authenticationResponseJSON);
        assertThatCode(()->target.verify(authenticationData, authenticationParameters)).doesNotThrowAnyException();
    }

    private AttestationObject createAttestationObject(String rpId, Challenge challenge) {
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName");

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

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getResponse();
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        return attestationObjectConverter.convert(registrationRequest.getAttestationObject());
    }
}
