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
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;

@SuppressWarnings("ConstantConditions")
class RegistrationResponseJSONVerificationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final String rpId = "example.com";
    private final Origin origin = new Origin("http://localhost");
    private final Challenge challenge = new DefaultChallenge();
    private final WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    private final NoneAttestationStatementVerifier noneAttestationStatementValidator = new NoneAttestationStatementVerifier();
    private final PackedAttestationStatementVerifier packedAttestationStatementValidator = new PackedAttestationStatementVerifier();
    private final FIDOU2FAttestationStatementVerifier fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementVerifier();
    private final AndroidKeyAttestationStatementVerifier androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementVerifier();
    private final TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate();
    private final WebAuthnManager target = new WebAuthnManager(
            Arrays.asList(
                    noneAttestationStatementValidator,
                    packedAttestationStatementValidator,
                    fidoU2FAttestationStatementValidator,
                    androidKeyAttestationStatementValidator),
            new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository),
            new DefaultSelfAttestationTrustworthinessVerifier(),
            objectConverter
    );

    @Test
    void test_with_registrationResponseJSON_as_string() {
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = createCredential();
        String registrationResponseJSON = objectConverter.getJsonConverter().writeValueAsString(credential);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()->target.parseRegistrationResponseJSON(registrationResponseJSON)).doesNotThrowAnyException();

        RegistrationData registrationData = target.parseRegistrationResponseJSON(registrationResponseJSON);
        assertThatCode(()->target.verify(registrationData, registrationParameters)).doesNotThrowAnyException();

        assertThatCode(()->target.verifyRegistrationResponseJSON(registrationResponseJSON, registrationParameters)).doesNotThrowAnyException();
    }

    @Test
    void test_with_registrationResponseJSON_as_InputStream() {
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = createCredential();
        byte[] registrationResponseJSON = objectConverter.getJsonConverter().writeValueAsBytes(credential);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()->target.parseRegistrationResponseJSON(new ByteArrayInputStream(registrationResponseJSON))).doesNotThrowAnyException();

        RegistrationData registrationData = target.parseRegistrationResponseJSON(new ByteArrayInputStream(registrationResponseJSON));
        assertThatCode(()->target.verify(registrationData, registrationParameters)).doesNotThrowAnyException();

        assertThatCode(()->target.verifyRegistrationResponseJSON(new ByteArrayInputStream(registrationResponseJSON), registrationParameters)).doesNotThrowAnyException();
    }

    private PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> createCredential(){
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
        return clientPlatform.create(credentialCreationOptions);
    }
}
