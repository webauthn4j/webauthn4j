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

import com.webauthn4j.anchor.TrustAnchorsResolver;
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
import com.webauthn4j.validator.CoreRegistrationDataValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

class FIDOAuthenticatorCoreRegistrationValidationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final Origin origin = new Origin("http://localhost");
    private final WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    private final NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private final PackedAttestationStatementValidator packedAttestationStatementValidator = new PackedAttestationStatementValidator();
    private final FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator();
    private final AndroidKeyAttestationStatementValidator androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementValidator();
    private final TrustAnchorsResolver trustAnchorsResolver = TestAttestationUtil.createTrustAnchorProviderWith3tierTestRootCACertificate();
    private final CoreRegistrationDataValidator target = new CoreRegistrationDataValidator(
            Arrays.asList(
                    noneAttestationStatementValidator,
                    packedAttestationStatementValidator,
                    fidoU2FAttestationStatementValidator,
                    androidKeyAttestationStatementValidator),
            new TrustAnchorCertPathTrustworthinessValidator(trustAnchorsResolver),
            new DefaultSelfAttestationTrustworthinessValidator(),
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

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();

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
        AuthenticatorAttestationResponse registrationRequest = credential.getAuthenticatorResponse();
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
                false
        );

        target.validate(coreRegistrationData, coreRegistrationParameters);
    }

}
