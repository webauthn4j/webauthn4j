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

package integration.scenario;

import com.webauthn4j.anchor.TrustAnchorsResolver;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.DefaultECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.*;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class FIDOU2FAuthenticatorRegistrationValidationTest {

    private JsonConverter jsonConverter = new JsonConverter();


    private Origin origin = new Origin("http://localhost");
    private ClientPlatform clientPlatform = new ClientPlatform(origin, new FIDOU2FAuthenticatorAdaptor());
    private NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator();
    private TrustAnchorsResolver trustAnchorsResolver = TestAttestationUtil.createTrustAnchorProviderWith2tierTestRootCACertificate();
    private WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(
            Arrays.asList(noneAttestationStatementValidator, fidoU2FAttestationStatementValidator),
            new TrustAnchorCertPathTrustworthinessValidator(trustAnchorsResolver),
            new DefaultECDAATrustworthinessValidator(),
            new DefaultSelfAttestationTrustworthinessValidator()
    );

    private AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(jsonConverter);

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

        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
        AuthenticatorAttestationResponse registrationRequest = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs clientExtensionResults = credential.getClientExtensionResults();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext
                = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                registrationRequest.getTransports(),
                clientExtensionJSON,
                serverProperty,
                false,
                Collections.emptyList()
        );

        WebAuthnRegistrationContextValidationResponse response = target.validate(registrationContext);

        assertAll(
                () -> assertThat(response.getCollectedClientData()).isNotNull(),
                () -> assertThat(response.getAttestationObject()).isNotNull(),
                () -> assertThat(response.getRegistrationExtensionsClientOutputs()).isNotNull()
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

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
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
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
        AuthenticatorAttestationResponse registrationRequest = credential.getAuthenticatorResponse();
        AuthenticationExtensionsClientOutputs clientExtensionResults = credential.getClientExtensionResults();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext
                = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                registrationRequest.getTransports(),
                clientExtensionJSON,
                serverProperty,
                false,
                Collections.emptyList()
        );

        WebAuthnRegistrationContextValidationResponse response = target.validate(registrationContext);

        assertAll(
                () -> assertThat(response.getCollectedClientData()).isNotNull(),
                () -> assertThat(response.getAttestationObject()).isNotNull(),
                () -> assertThat(response.getRegistrationExtensionsClientOutputs()).isNotNull()
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
        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions, registrationEmulationOption).getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), registrationRequest.getTransports(), serverProperty, false);
        assertThrows(MaliciousDataException.class,
                () -> target.validate(registrationContext)
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

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), registrationRequest.getTransports(), serverProperty, false);
        assertThrows(BadChallengeException.class,
                () -> target.validate(registrationContext)
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
        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), registrationRequest.getTransports(), serverProperty, false);
        assertThrows(BadOriginException.class,
                () -> target.validate(registrationContext)
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
        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), registrationRequest.getTransports(), serverProperty, false);
        assertThrows(BadRpIdException.class,
                () -> target.validate(registrationContext)
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

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), registrationRequest.getTransports(), serverProperty, false);
        WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(
                Collections.singletonList(fidoU2FAttestationStatementValidator),
                new TrustAnchorCertPathTrustworthinessValidator(mock(TrustAnchorsResolver.class)),
                new DefaultECDAATrustworthinessValidator(),
                new DefaultSelfAttestationTrustworthinessValidator()
        );
        assertThrows(BadAttestationStatementException.class,
                () -> target.validate(registrationContext)
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

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
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
        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions, registrationEmulationOption).getAuthenticatorResponse();

        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext =
                new WebAuthnRegistrationContext(
                        registrationRequest.getClientDataJSON(),
                        registrationRequest.getAttestationObject(),
                        registrationRequest.getTransports(),
                        serverProperty,
                        false);
        assertThrows(BadSignatureException.class,
                () -> target.validate(registrationContext)
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

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
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

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();

        CollectedClientData maliciousClientData = new CollectedClientData(ClientDataType.CREATE, challenge, phishingSiteClaimingOrigin, null);
        byte[] maliciousClientDataBytes = new CollectedClientDataConverter(jsonConverter).convertToBytes(maliciousClientData);
        ServerProperty serverProperty = new ServerProperty(validSiteOrigin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(maliciousClientDataBytes,
                registrationRequest.getAttestationObject(), registrationRequest.getTransports(), serverProperty, false);
        assertThrows(BadSignatureException.class,
                () -> target.validate(registrationContext)
        );
    }
}
