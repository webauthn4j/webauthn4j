package integration.scenario.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.async.WebAuthnAsyncManager;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.BadTopOriginException;
import org.junit.jupiter.api.Test;
import test.WebAuthnTestUtil;

import java.util.Collections;

import static org.assertj.core.api.Assertions.*;
import static test.WebAuthnTestUtil.toRegistrationRequest;

class CrossOriginRegistrationVerificationTest {

    @Test
    void shouldVerifySuccessfullyWhenClientDataTopOriginMatchesServerPropertyTopOrigin(){
        var webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
        var webAuthnAsyncManager = WebAuthnAsyncManager.createNonStrictWebAuthnAsyncManager();
        var challenge = new DefaultChallenge();

        var origin = new Origin("http://localhost");
        var topOrigin = new Origin("http://example.com");
        var serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(challenge)
                .topOrigin(topOrigin)
                .build();

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(serverProperty.getRpId(), "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.DIRECT,
                new AuthenticationExtensionsClientInputs<>()
        );

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithNoneAuthenticator(origin, topOrigin);
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatCode(()->webAuthnManager.verify(registrationRequest, registrationParameters)).doesNotThrowAnyException();
        assertThat(webAuthnAsyncManager.verify(registrationRequest, registrationParameters))
                .succeedsWithin(java.time.Duration.ofSeconds(5));
    }


    @Test
    void shouldVerifyFailWhenClientDataTopOriginDoesNotMatchServerPropertyTopOrigin(){
        var webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
        var webAuthnAsyncManager = WebAuthnAsyncManager.createNonStrictWebAuthnAsyncManager();
        var challenge = new DefaultChallenge();

        var origin = new Origin("http://localhost");
        var topOrigin = new Origin("http://example.com");
        var serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(challenge)
                .topOrigin(topOrigin)
                .build();

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(serverProperty.getRpId(), "example.com"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.DIRECT,
                new AuthenticationExtensionsClientInputs<>()
        );

        var clientPlatform = WebAuthnTestUtil.createClientPlatformWithNoneAuthenticator(origin, new Origin("http://example.net"));
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);

        var registrationRequest = toRegistrationRequest(credential);
        var registrationParameters = new RegistrationParameters(serverProperty, null, false, true);

        //Act
        assertThatThrownBy(()->webAuthnManager.verify(registrationRequest, registrationParameters)).isInstanceOf(BadTopOriginException.class);
        assertThat(webAuthnAsyncManager.verify(registrationRequest, registrationParameters))
                .failsWithin(java.time.Duration.ofSeconds(5)).withThrowableThat().havingCause().isInstanceOf(BadTopOriginException.class);
    }
}
