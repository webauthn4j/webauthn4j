/*
 * Copyright 2018 the original author or authors.
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
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Integration test for ML-DSA (FIPS 204) post-quantum signature algorithms.
 * Tests the full WebAuthn registration + authentication flow using ML-DSA authenticator emulation.
 */
@EnabledForJreRange(min = JRE.JAVA_24)
class MLDSAAuthenticatorRegistrationAndAuthenticationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);

    private final Origin origin = new Origin("http://example.com");
    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final WebAuthnManager target = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    static Stream<COSEAlgorithmIdentifier> mlDsaAlgorithms() {
        return Stream.of(
                COSEAlgorithmIdentifier.ML_DSA_44,
                COSEAlgorithmIdentifier.ML_DSA_65,
                COSEAlgorithmIdentifier.ML_DSA_87
        );
    }

    @ParameterizedTest(name = "{argumentsWithNames}")
    @MethodSource("mlDsaAlgorithms")
    void registration_and_authentication_should_succeed(COSEAlgorithmIdentifier alg) {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        // Registration
        CredentialRecord credentialRecord = createCredentialRecord(rpId, challenge, alg);

        // Authentication
        challenge = new DefaultChallenge();
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions);

        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId(rpId)
                .challenge(challenge)
                .build();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
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

        assertThatCode(() -> target.verify(authenticationRequest, authenticationParameters)).doesNotThrowAnyException();
    }

    private CredentialRecord createCredentialRecord(String rpId, Challenge challenge, COSEAlgorithmIdentifier alg) {
        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)),
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
