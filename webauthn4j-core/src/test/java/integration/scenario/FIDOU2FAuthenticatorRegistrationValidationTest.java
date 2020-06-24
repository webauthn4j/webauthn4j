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
import com.webauthn4j.anchor.TrustAnchorsResolver;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.*;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class FIDOU2FAuthenticatorRegistrationValidationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();


    private final Origin origin = new Origin("http://localhost");
    private final ClientPlatform clientPlatform = new ClientPlatform(origin, new FIDOU2FAuthenticatorAdaptor());
    private final NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private final FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator();
    private final TrustAnchorsResolver trustAnchorsResolver = TestAttestationUtil.createTrustAnchorProviderWith2tierTestRootCACertificate();
    private final WebAuthnManager target = new WebAuthnManager(
            Arrays.asList(noneAttestationStatementValidator, fidoU2FAttestationStatementValidator),
            new TrustAnchorCertPathTrustworthinessValidator(trustAnchorsResolver),
            new DefaultSelfAttestationTrustworthinessValidator()
    );

    private final AuthenticatorTransportConverter authenticatorTransportConverter = new AuthenticatorTransportConverter();
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void validate_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );

        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput<?>> credential = clientPlatform.create(credentialCreationOptions);
        AuthenticatorAttestationResponse authenticatorAttestationResponse = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput<?>> clientExtensionResults = credential.getClientExtensionResults();
        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                clientExtensionJSON,
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        RegistrationData response = target.validate(registrationRequest, registrationParameters);

        assertAll(
                () -> assertThat(response.getCollectedClientData()).isNotNull(),
                () -> assertThat(response.getAttestationObject()).isNotNull(),
                () -> assertThat(response.getClientExtensions()).isNotNull()
        );
    }

    @Test
    void validate_with_direct_attestation_conveyance_preference_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.DIRECT,
                extensions
        );
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput<?>> credential = clientPlatform.create(credentialCreationOptions);
        AuthenticatorAttestationResponse authenticatorAttestationResponse = credential.getAuthenticatorResponse();
        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput<?>> clientExtensionResults = credential.getClientExtensionResults();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                clientExtensionJSON,
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        RegistrationData response = target.validate(registrationRequest, registrationParameters);


        assertAll(
                () -> assertThat(response.getCollectedClientData()).isNotNull(),
                () -> assertThat(response.getAttestationObject()).isNotNull(),
                () -> assertThat(response.getClientExtensions()).isNotNull()
        );
    }

    @Test
    void validate_with_bad_clientData_type_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );

        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(ClientDataType.GET, challenge);
        RegistrationEmulationOption registrationEmulationOption = new RegistrationEmulationOption();
        registrationEmulationOption.setCollectedClientData(collectedClientData);
        registrationEmulationOption.setCollectedClientDataOverrideEnabled(true);
        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions, registrationEmulationOption).getAuthenticatorResponse();

        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );


        assertThrows(InconsistentClientDataTypeException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }

    @Test
    void validate_with_bad_challenge_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        Challenge badChallenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                badChallenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );

        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        assertThrows(BadChallengeException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }

    @Test
    void validate_with_bad_origin_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        Origin badOrigin = new Origin("http://bad.origin.example.net");
        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );

        clientPlatform.setOrigin(badOrigin); //bad origin
        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        assertThrows(BadOriginException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }

    @Test
    void validate_with_bad_rpId_test() {
        String rpId = "example.com";
        String badRpId = "example.net";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(badRpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );
        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        assertThrows(BadRpIdException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }

    @Test
    void validate_with_bad_attestationStatement_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );

        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );
        WebAuthnManager target = new WebAuthnManager(
                Collections.singletonList(fidoU2FAttestationStatementValidator),
                new TrustAnchorCertPathTrustworthinessValidator(mock(TrustAnchorsResolver.class)),
                new DefaultSelfAttestationTrustworthinessValidator()
        );

        assertThrows(BadAttestationStatementException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }

    @Test
    void validate_invalid_format_attestation_signature_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "valid.site.example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.DIRECT,
                extensions
        );


        RegistrationEmulationOption registrationEmulationOption = new RegistrationEmulationOption();
        registrationEmulationOption.setSignatureOverrideEnabled(true);
        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions, registrationEmulationOption).getAuthenticatorResponse();

        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        assertThrows(BadSignatureException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }

    @Test
    void validate_malicious_client_data_test() {
        Origin phishingSiteOrigin = new Origin("http://phishing.site.example.com");
        Origin validSiteOrigin = new Origin("http://valid.site.example.com");
        Origin phishingSiteClaimingOrigin = new Origin("http://valid.site.example.com");

        ClientPlatform clientPlatform = new ClientPlatform(phishingSiteOrigin, new FIDOU2FAuthenticatorAdaptor()); // client platform loads phishing site
        String rpId = "valid.site.example.com";
        Challenge challenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "valid.site.example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.DIRECT,
                extensions
        );

        AuthenticatorAttestationResponse authenticatorAttestationResponse = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        CollectedClientData maliciousClientData = new CollectedClientData(ClientDataType.CREATE, challenge, phishingSiteClaimingOrigin, null);
        byte[] maliciousClientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(maliciousClientData);
        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
        ServerProperty serverProperty = new ServerProperty(validSiteOrigin, rpId, challenge, null);
        RegistrationRequest registrationRequest
                = new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                maliciousClientDataBytes,
                transports
        );
        RegistrationParameters registrationParameters
                = new RegistrationParameters(
                serverProperty,
                false,
                true,
                Collections.emptyList()
        );

        assertThrows(BadSignatureException.class,
                () -> target.validate(registrationRequest, registrationParameters)
        );
    }
}
