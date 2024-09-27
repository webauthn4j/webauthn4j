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

package integration.scenario.fido;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
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
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.CoreRegistrationDataVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

@SuppressWarnings("ConstantConditions")
class FIDOAuthenticatorCoreRegistrationValidationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final Origin origin = new Origin("http://localhost");
    private final WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    private final NoneAttestationStatementVerifier noneAttestationStatementValidator = new NoneAttestationStatementVerifier();
    private final PackedAttestationStatementVerifier packedAttestationStatementValidator = new PackedAttestationStatementVerifier();
    private final FIDOU2FAttestationStatementVerifier fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementVerifier();
    private final AndroidKeyAttestationStatementVerifier androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementVerifier();
    private final TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate();
    private final CoreRegistrationDataVerifier target = new CoreRegistrationDataVerifier(
            Arrays.asList(
                    noneAttestationStatementValidator,
                    packedAttestationStatementValidator,
                    fidoU2FAttestationStatementValidator,
                    androidKeyAttestationStatementValidator),
            new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository),
            new DefaultSelfAttestationTrustworthinessVerifier(),
            Collections.emptyList(),
            objectConverter
    );

    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);

    @Test
    void validate_RegistrationRequest_with_packed_attestation_statement_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
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
        AttestationObject attestationObject = attestationObjectConverter.convert(registrationRequest.getAttestationObject());
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        CoreRegistrationData coreRegistrationData
                = new CoreRegistrationData(
                attestationObject,
                registrationRequest.getAttestationObject(),
                MessageDigestUtil.createSHA256().digest(registrationRequest.getClientDataJSON())
        );
        CoreRegistrationParameters coreRegistrationParameters = new CoreRegistrationParameters(
                serverProperty,
                null,
                false
        );

        target.verify(coreRegistrationData, coreRegistrationParameters);
    }

}
