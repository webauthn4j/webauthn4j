package integration.scenario.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.async.WebAuthnAsyncManager;
import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.async.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.packed.PackedAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.tpm.TPMAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.junit.jupiter.api.Test;
import test.WebAuthnTestUtil;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static test.WebAuthnTestUtil.toRegistrationRequest;

@SuppressWarnings("DataFlowIssue")
class AttestationVariationTest {

    private final TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate();
    private final TrustAnchorAsyncRepository trustAnchorAsyncRepository = TestAttestationUtil.createTrustAnchorAsyncRepositoryWith3tierTestRootCACertificate();

    @Test
    void should_success_when_PackedAttestationStatementVerifier_is_used_for_packed_attestation(){
        var packedAttestationStatementVerifier = new PackedAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(packedAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var packedAttestationStatementAsyncVerifier = new PackedAttestationStatementAsyncVerifier();
        var webAuthnAsyncManager = new WebAuthnAsyncManager(Collections.singletonList(packedAttestationStatementAsyncVerifier), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepository), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

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
        assertThatCode(()->webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_AndroidKeyAttestationStatementVerifier_is_used_for_android_key_attestation(){
        var androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(androidKeyAttestationStatementValidator), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var androidKeyAttestationStatementAsyncValidator = new AndroidKeyAttestationStatementAsyncVerifier();
        var webAuthnAsyncManager = new WebAuthnAsyncManager(Collections.singletonList(androidKeyAttestationStatementAsyncValidator), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepository), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

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
        assertThatCode(()->webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_AndroidSafetyNetAttestationStatementVerifier_is_used_for_android_safety_net_attestation(){
        var androidSafetyNetAttestationStatementVerifier = new AndroidSafetyNetAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(androidSafetyNetAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var androidSafetyNetAttestationStatementAsyncVerifier = new AndroidSafetyNetAttestationStatementAsyncVerifier();
        var webAuthnAsyncManager = new WebAuthnAsyncManager(Collections.singletonList(androidSafetyNetAttestationStatementAsyncVerifier), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepository), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

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
        assertThatCode(()->webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_TPMAttestationStatementVerifier_is_used_for_tpm_attestation(){
        var tpmAttestationStatementVerifier = new TPMAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(tpmAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository), new DefaultSelfAttestationTrustworthinessVerifier());
        var tpmAttestationStatementAsyncVerifier = new TPMAttestationStatementAsyncVerifier();
        var webAuthnAsyncManager = new WebAuthnAsyncManager(Collections.singletonList(tpmAttestationStatementAsyncVerifier), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepository), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

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
        assertThatCode(()->webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_FIDOU2FAttestationStatementVerifier_is_used_for_fido_u2f_attestation(){
        TrustAnchorRepository trustAnchorRepositoryWith2tierTestRootCACertificate = TestAttestationUtil.createTrustAnchorRepositoryWith2tierTestRootCACertificate();
        TrustAnchorAsyncRepository trustAnchorAsyncRepositoryWith2tierTestRootCACertificate = TestAttestationUtil.createTrustAnchorAsyncRepositoryWith2tierTestRootCACertificate();

        var fidoU2FAttestationStatementVerifier = new FIDOU2FAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(fidoU2FAttestationStatementVerifier), new DefaultCertPathTrustworthinessVerifier(trustAnchorRepositoryWith2tierTestRootCACertificate), new DefaultSelfAttestationTrustworthinessVerifier());
        var fidoU2FAttestationStatementAsyncVerifier = new FIDOU2FAttestationStatementAsyncVerifier();
        var webAuthnAsyncManager = new WebAuthnAsyncManager(Collections.singletonList(fidoU2FAttestationStatementAsyncVerifier), new DefaultCertPathTrustworthinessAsyncVerifier(trustAnchorAsyncRepositoryWith2tierTestRootCACertificate), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

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
        assertThatCode(()->webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void should_success_when_NoneAttestationStatementVerifier_is_used_for_none_attestation(){
        var noneAttestationStatementVerifier = new NoneAttestationStatementVerifier();
        var webAuthnManager = new WebAuthnManager(Collections.singletonList(noneAttestationStatementVerifier), new NullCertPathTrustworthinessVerifier(), new DefaultSelfAttestationTrustworthinessVerifier());
        var noneAttestationStatementAsyncVerifier = new NoneAttestationStatementAsyncVerifier();
        var webAuthnAsyncManager = new WebAuthnAsyncManager(Collections.singletonList(noneAttestationStatementAsyncVerifier), new NullCertPathTrustworthinessAsyncVerifier(), new DefaultSelfAttestationTrustworthinessAsyncVerifier());

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
        assertThatCode(()->webAuthnAsyncManager.verify(registrationRequest, registrationParameters).toCompletableFuture().get()).doesNotThrowAnyException();
    }


}
