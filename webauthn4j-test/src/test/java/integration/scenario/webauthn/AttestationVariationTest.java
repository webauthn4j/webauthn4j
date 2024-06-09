package integration.scenario.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.reactive.WebAuthnReactiveManager;
import com.webauthn4j.reactive.anchor.TrustAnchorReactiveRepository;
import com.webauthn4j.reactive.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.none.NoneAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.packed.PackedAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.tpm.TPMAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessReactiveVerifier;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.junit.jupiter.api.Test;
import test.WebAuthnTestUtil;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static test.WebAuthnTestUtil.toRegistrationRequest;

@SuppressWarnings("DataFlowIssue")
public class AttestationVariationTest {

    private final TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate();
    private final TrustAnchorReactiveRepository trustAnchorReactiveRepository = TestAttestationUtil.createTrustAnchorReactiveRepositoryWith3tierTestRootCACertificate();

    @Test
    void should_success_when_PackedAttestationStatementVerifier_is_used_for_packed_attestation(){
        var packedAttestationStatementVerifier = new PackedAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(packedAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var packedAttestationStatementReactiveVerifier = new PackedAttestationStatementReactiveVerifier();
        var webAuthnReactiveManager = new WebAuthnReactiveManager(Collections.singletonList(packedAttestationStatementReactiveVerifier), new DefaultCertPathTrustworthinessReactiveVerifier(trustAnchorReactiveRepository), new DefaultSelfAttestationTrustworthinessReactiveVerifier());

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
        assertThatCode(()->webAuthnReactiveManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_AndroidKeyAttestationStatementVerifier_is_used_for_android_key_attestation(){
        var androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(androidKeyAttestationStatementValidator), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var androidKeyAttestationStatementReactiveValidator = new AndroidKeyAttestationStatementReactiveVerifier();
        var webAuthnReactiveManager = new WebAuthnReactiveManager(Collections.singletonList(androidKeyAttestationStatementReactiveValidator), new DefaultCertPathTrustworthinessReactiveVerifier(trustAnchorReactiveRepository), new DefaultSelfAttestationTrustworthinessReactiveVerifier());

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

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithAndroidKeyAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()->webAuthnReactiveManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_AndroidSafetyNetAttestationStatementVerifier_is_used_for_android_safety_net_attestation(){
        var androidSafetyNetAttestationStatementVerifier = new AndroidSafetyNetAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(androidSafetyNetAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var androidSafetyNetAttestationStatementReactiveVerifier = new AndroidSafetyNetAttestationStatementReactiveVerifier();
        var webAuthnReactiveManager = new WebAuthnReactiveManager(Collections.singletonList(androidSafetyNetAttestationStatementReactiveVerifier), new DefaultCertPathTrustworthinessReactiveVerifier(trustAnchorReactiveRepository), new DefaultSelfAttestationTrustworthinessReactiveVerifier());

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

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithAndroidSafetyNetAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()->webAuthnReactiveManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_TPMAttestationStatementVerifier_is_used_for_tpm_attestation(){
        var tpmAttestationStatementVerifier = new TPMAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(tpmAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var tpmAttestationStatementReactiveVerifier = new TPMAttestationStatementReactiveVerifier();
        var webAuthnReactiveManager = new WebAuthnReactiveManager(Collections.singletonList(tpmAttestationStatementReactiveVerifier), new DefaultCertPathTrustworthinessReactiveVerifier(trustAnchorReactiveRepository), new DefaultSelfAttestationTrustworthinessReactiveVerifier());

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

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithTPMAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()->webAuthnReactiveManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_FIDOU2FAttestationStatementVerifier_is_used_for_fido_u2f_attestation(){
        TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith2tierTestRootCACertificate();
        TrustAnchorReactiveRepository trustAnchorReactiveRepository = TestAttestationUtil.createTrustAnchorReactiveRepositoryWith2tierTestRootCACertificate();

        var fidoU2FAttestationStatementVerifier = new FIDOU2FAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(fidoU2FAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var fidoU2FAttestationStatementReactiveVerifier = new FIDOU2FAttestationStatementReactiveVerifier();
        var webAuthnReactiveManager = new WebAuthnReactiveManager(Collections.singletonList(fidoU2FAttestationStatementReactiveVerifier), new DefaultCertPathTrustworthinessReactiveVerifier(trustAnchorReactiveRepository), new DefaultSelfAttestationTrustworthinessReactiveVerifier());

        var origin = new Origin("http://localhost");
        var serverProperty = new ServerProperty(origin, "example.com", new DefaultChallenge(), null);

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(serverProperty.getRpId(), "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                serverProperty.getChallenge(),
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, false, UserVerificationRequirement.PREFERRED),
                AttestationConveyancePreference.DIRECT,
                new AuthenticationExtensionsClientInputs<>()
        );

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithFIDOU2FAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()->webAuthnReactiveManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_NoneAttestationStatementVerifier_is_used_for_none_attestation(){
        var noneAttestationStatementVerifier = new NoneAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(noneAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var noneAttestationStatementReactiveVerifier = new NoneAttestationStatementReactiveVerifier();
        var webAuthnReactiveManager = new WebAuthnReactiveManager(Collections.singletonList(noneAttestationStatementReactiveVerifier), new DefaultCertPathTrustworthinessReactiveVerifier(trustAnchorReactiveRepository), new DefaultSelfAttestationTrustworthinessReactiveVerifier());

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

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithNoneAuthenticator(origin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThatCode(()->webAuthnReactiveManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }


}
