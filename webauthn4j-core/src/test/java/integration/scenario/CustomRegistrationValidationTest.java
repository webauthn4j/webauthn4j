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
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CustomRegistrationValidationTest {

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
    void CustomRegistrationValidator_test() {
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
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        Set<String> transports = authenticatorTransportConverter.convertSetToStringSet(authenticatorAttestationResponse.getTransports());
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

        target.getRegistrationDataValidator().getCustomRegistrationValidators().add(registrationObject ->
                assertThat(registrationObject).isNotNull());
        target.validate(registrationRequest, registrationParameters);

    }

}
