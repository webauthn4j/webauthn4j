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

import com.webauthn4j.async.WebAuthnAsyncManager;
import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.async.metadata.anchor.AggregatingTrustAnchorAsyncRepository;
import com.webauthn4j.async.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.packed.PackedAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.tpm.TPMAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatCode;

@SuppressWarnings("ConstantConditions")
class AttestationVariationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final String rpId = "example.com";
    private final Origin origin = new Origin("http://localhost");
    private final TrustAnchorAsyncRepository trustAnchorAsyncRepository = new AggregatingTrustAnchorAsyncRepository(
            TestAttestationUtil.createTrustAnchorAsyncRepositoryWith2tierTestRootCACertificate(),
            TestAttestationUtil.createTrustAnchorAsyncRepositoryWith3tierTestRootCACertificate()
    );
    private final WebAuthnAsyncManager target = new WebAuthnAsyncManager(
            Arrays.asList(
                    new PackedAttestationStatementAsyncVerifier(),
                    new FIDOU2FAttestationStatementAsyncVerifier(),
                    new AndroidKeyAttestationStatementAsyncVerifier(),
                    new AndroidSafetyNetAttestationStatementAsyncVerifier(),
                    new AppleAnonymousAttestationStatementAsyncVerifier(),
                    new TPMAttestationStatementAsyncVerifier(),
                    new NoneAttestationStatementAsyncVerifier()
            ), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepository), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void verify_RegistrationRequest_with_packed_attestation_statement_test() {
        WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
        ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()-> target.verify(createRegistrationRequest(clientPlatform, rpId, challenge), registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void verify_RegistrationRequest_with_fido_u2f_attestation_statement_test() {
        FIDOU2FAuthenticatorAdaptor fidou2FAuthenticatorAdaptor = new FIDOU2FAuthenticatorAdaptor(EmulatorUtil.FIDO_U2F_AUTHENTICATOR);
        ClientPlatform clientPlatform = new ClientPlatform(origin, fidou2FAuthenticatorAdaptor);

        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()-> target.verify(createRegistrationRequest(clientPlatform, rpId, challenge), registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void verify_RegistrationRequest_with_android_key_attestation_statement_test() {
        WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.ANDROID_KEY_AUTHENTICATOR);
        ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()-> target.verify(createRegistrationRequest(clientPlatform, rpId, challenge), registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void verify_RegistrationRequest_with_android_safety_net_attestation_statement_test() {
        WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.ANDROID_SAFETY_NET_AUTHENTICATOR);
        ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()-> target.verify(createRegistrationRequest(clientPlatform, rpId, challenge), registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void verify_RegistrationRequest_with_tpm_attestation_statement_test() {
        WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.TPM_AUTHENTICATOR);
        ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

        Challenge challenge = new DefaultChallenge();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                pubKeyCredParams,
                false
        );

        assertThatCode(()-> target.verify(createRegistrationRequest(clientPlatform, rpId, challenge), registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }



    private RegistrationRequest createRegistrationRequest(ClientPlatform clientPlatform, String rpId, Challenge challenge){
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
                AttestationConveyancePreference.DIRECT,
                extensions
        );
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
        AuthenticatorAttestationResponse registrationRequest = credential.getResponse();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensionResults = credential.getClientExtensionResults();
        Set<String> transports = Collections.emptySet();
        String clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        return new RegistrationRequest(
                registrationRequest.getAttestationObject(),
                registrationRequest.getClientDataJSON(),
                clientExtensionJSON,
                transports
        );
    }
}
