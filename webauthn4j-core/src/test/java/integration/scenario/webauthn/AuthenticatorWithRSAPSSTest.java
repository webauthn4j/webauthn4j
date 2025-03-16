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
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.client.ClientPlatform;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;

@SuppressWarnings("ConstantConditions")
class AuthenticatorWithRSAPSSTest {

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

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge);

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

    private CredentialRecord createCredentialRecord(String rpId, Challenge challenge) {

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.PS256)),
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
