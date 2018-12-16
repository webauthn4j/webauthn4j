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

import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.anchor.TrustAnchorProvider;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.authenticator.model.WebAuthnModelAuthenticatorAdaptor;
import com.webauthn4j.test.client.*;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.DefaultECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;
import org.junit.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

public class UserVerifyingAuthenticatorRegistrationValidationTest {

    private Origin origin = new Origin("http://localhost");
    private WebAuthnModelAuthenticatorAdaptor webAuthnModelAuthenticatorAdaptor = new WebAuthnModelAuthenticatorAdaptor();
    private ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnModelAuthenticatorAdaptor);
    private NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private PackedAttestationStatementValidator packedAttestationStatementValidator = new PackedAttestationStatementValidator();
    private FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator();
    private AndroidKeyAttestationStatementValidator androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementValidator();
    private TrustAnchorProvider trustAnchorProvider = TestUtil.createTrustAnchorProviderWith3tierTestRootCACertificate();
    private WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(
            Arrays.asList(
                    noneAttestationStatementValidator,
                    packedAttestationStatementValidator,
                    fidoU2FAttestationStatementValidator,
                    androidKeyAttestationStatementValidator),
            new TrustAnchorCertPathTrustworthinessValidator(trustAnchorProvider),
            new DefaultECDAATrustworthinessValidator(),
            new DefaultSelfAttestationTrustworthinessValidator()
    );

    @Test
    public void validate_WebAuthnRegistrationContext_with_none_attestation_statement_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();
        authenticatorSelectionCriteria.setAuthenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM);
        authenticatorSelectionCriteria.setRequireResidentKey(true);
        authenticatorSelectionCriteria.setUserVerificationRequirement(UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PUBLIC_KEY);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PUBLIC_KEY);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        credentialCreationOptions.setAuthenticatorSelection(authenticatorSelectionCriteria);
        credentialCreationOptions.setPubKeyCredParams(Collections.singletonList(publicKeyCredentialParameters));
        credentialCreationOptions.setUser(publicKeyCredentialUserEntity);

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext
                = new WebAuthnRegistrationContext(
                    registrationRequest.getClientDataJSON(),
                    registrationRequest.getAttestationObject(),
                    registrationRequest.getClientExtensionsJSON(),
                    serverProperty,
                    false,
                    Collections.emptyList()
                );

        WebAuthnRegistrationContextValidationResponse response = target.validate(registrationContext);

        assertThat(response.getCollectedClientData()).isNotNull();
        assertThat(response.getAttestationObject()).isNotNull();
        assertThat(response.getClientExtensionOutputs()).isNotNull();
    }

    @Test
    public void validate_WebAuthnRegistrationContext_with_packed_attestation_statement_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();
        authenticatorSelectionCriteria.setAuthenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM);
        authenticatorSelectionCriteria.setRequireResidentKey(true);
        authenticatorSelectionCriteria.setUserVerificationRequirement(UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PUBLIC_KEY);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PUBLIC_KEY);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.DIRECT);
        credentialCreationOptions.setAuthenticatorSelection(authenticatorSelectionCriteria);
        credentialCreationOptions.setPubKeyCredParams(Collections.singletonList(publicKeyCredentialParameters));
        credentialCreationOptions.setUser(publicKeyCredentialUserEntity);
        Map<String, ClientExtensionInput> extensions = new HashMap<>();

        credentialCreationOptions.setExtensions(extensions);

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext
                = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                registrationRequest.getClientExtensionsJSON(),
                serverProperty,
                false,
                Collections.emptyList()
        );

        WebAuthnRegistrationContextValidationResponse response = target.validate(registrationContext);

        assertThat(response.getCollectedClientData()).isNotNull();
        assertThat(response.getAttestationObject()).isNotNull();
        assertThat(response.getClientExtensionOutputs()).isNotNull();
    }

    @Test(expected = UnexpectedExtensionException.class)
    public void validate_WebAuthnRegistrationContext_with_unexpected_extension_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();
        authenticatorSelectionCriteria.setAuthenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM);
        authenticatorSelectionCriteria.setRequireResidentKey(true);
        authenticatorSelectionCriteria.setUserVerificationRequirement(UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PUBLIC_KEY);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PUBLIC_KEY);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        credentialCreationOptions.setAuthenticatorSelection(authenticatorSelectionCriteria);
        credentialCreationOptions.setPubKeyCredParams(Collections.singletonList(publicKeyCredentialParameters));
        credentialCreationOptions.setUser(publicKeyCredentialUserEntity);
        Map<String, ClientExtensionInput> extensions = new HashMap<>();
        extensions.put(SupportedExtensionsClientExtensionInput.ID, new SupportedExtensionsClientExtensionInput(true));
        credentialCreationOptions.setExtensions(extensions);

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        List<String> expectedExtensions = Collections.singletonList("uvm");
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                registrationRequest.getClientDataJSON(),
                registrationRequest.getAttestationObject(),
                registrationRequest.getClientExtensionsJSON(),
                serverProperty,
                false,
                expectedExtensions
        );
        target.validate(registrationContext);
    }
}
