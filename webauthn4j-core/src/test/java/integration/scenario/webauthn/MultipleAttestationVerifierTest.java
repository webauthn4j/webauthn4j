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
import com.webauthn4j.async.WebAuthnAsyncManager;
import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.packed.PackedAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;
import test.WebAuthnTestUtil;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static test.WebAuthnTestUtil.toRegistrationRequest;

@SuppressWarnings("ConstantConditions")
class MultipleAttestationVerifierTest {

    private final TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate();
    private final TrustAnchorAsyncRepository trustAnchorAsyncRepository = TestAttestationUtil.createTrustAnchorAsyncRepositoryWith3tierTestRootCACertificate();

    private final PackedAttestationStatementVerifier packedAttestationStatementVerifier = new PackedAttestationStatementVerifier();
    private final NoneAttestationStatementVerifier noneAttestationStatementVerifier = new NoneAttestationStatementVerifier();
    private final WebAuthnManager webAuthnManager = new WebAuthnManager(Lists.list(packedAttestationStatementVerifier, noneAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
    private final PackedAttestationStatementAsyncVerifier packedAttestationStatementAsyncVerifier = new PackedAttestationStatementAsyncVerifier();
    private final NoneAttestationStatementAsyncVerifier noneAttestationStatementAsyncVerifier = new NoneAttestationStatementAsyncVerifier();
    private final WebAuthnAsyncManager webAuthnAsyncManager = new WebAuthnAsyncManager(Lists.list(packedAttestationStatementAsyncVerifier, noneAttestationStatementAsyncVerifier), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepository), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

    @Test
    void should_success_when_multiple_AttestationStatementVerifier_is_used_for_packed_attestation_statement(){

        var origin = new Origin("http://localhost");
        var serverProperty = new ServerProperty(origin, "example.com", new DefaultChallenge(), null);

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(serverProperty.getRpId(), "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                serverProperty.getChallenge(),
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.DIRECT,
                new AuthenticationExtensionsClientInputs<>()
        );

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithPackedAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()-> webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_multiple_AttestationStatementVerifier_is_used_for_none_attestation_statement(){

        var origin = new Origin("http://localhost");
        var serverProperty = new ServerProperty(origin, "example.com", new DefaultChallenge(), null);

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(serverProperty.getRpId(), "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                serverProperty.getChallenge(),
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<>()
        );

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithPackedAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()-> webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }


}
