package integration.scenario.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.async.WebAuthnAsyncManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.verifier.exception.BadTopOriginException;
import org.junit.jupiter.api.Test;
import test.WebAuthnTestUtil;

import java.util.Collections;

import static org.assertj.core.api.Assertions.*;


class CrossOriginAuthenticationVerificationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);

    private final Origin origin = new Origin("http://localhost");
    private final Origin topOrigin = new Origin("http://example.com");

    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter
            = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
    private final ClientPlatform clientPlatform = WebAuthnTestUtil.createClientPlatformWithNoneAuthenticator(origin, topOrigin);

    @Test
    void shouldVerifySuccessfullyWhenClientDataTopOriginMatchesServerPropertyTopOrigin() {
        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions);

        ServerProperty serverProperty =
                ServerProperty.builder()
                        .origin(origin)
                        .rpId(rpId)
                        .challenge(challenge)
                        .topOrigin(topOrigin)
                        .build();

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatCode(()->webAuthnManager.verify(webAuthnAuthenticationRequest, authenticationParameters)).doesNotThrowAnyException();
    }

    @Test
    void shouldVerifyAsyncSuccessfullyWhenClientDataTopOriginMatchesServerPropertyTopOrigin() {
        WebAuthnAsyncManager webAuthnManager = WebAuthnAsyncManager.createNonStrictWebAuthnAsyncManager(objectConverter);

        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions);

        ServerProperty serverProperty =
                ServerProperty.builder()
                        .origin(origin)
                        .rpId(rpId)
                        .challenge(challenge)
                        .topOrigin(topOrigin)
                        .build();

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThat(webAuthnManager.verify(webAuthnAuthenticationRequest, authenticationParameters)).succeedsWithin(java.time.Duration.ofSeconds(5));
    }

    @Test
    void shouldVerifyFailWhenClientDataTopOriginDoesNotMatchServerPropertyTopOrigin() {
        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions);

        ServerProperty serverProperty =
                ServerProperty.builder()
                        .origin(origin)
                        .rpId(rpId)
                        .challenge(challenge)
                        .topOrigin(new Origin("http://bad.example.com"))
                        .build();

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThatThrownBy(()->webAuthnManager.verify(webAuthnAuthenticationRequest, authenticationParameters)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifyAsyncFailWhenClientDataTopOriginDoesNotMatchServerPropertyTopOrigin() {
        WebAuthnAsyncManager webAuthnManager = WebAuthnAsyncManager.createNonStrictWebAuthnAsyncManager(objectConverter);

        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();

        // create
        var credentialRecord = createCredentialRecord(rpId, challenge);

        // get
        var credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                0L,
                rpId,
                null,
                UserVerificationRequirement.REQUIRED,
                null
        );
        var publicKeyCredential = clientPlatform.get(credentialRequestOptions);

        ServerProperty serverProperty =
                ServerProperty.builder()
                        .origin(origin)
                        .rpId(rpId)
                        .challenge(challenge)
                        .topOrigin(new Origin("http://bad.example.com"))
                        .build();

        AuthenticationRequest webAuthnAuthenticationRequest = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                authenticationExtensionsClientOutputsConverter.convertToString(publicKeyCredential.getClientExtensionResults()),
                publicKeyCredential.getResponse().getSignature()
        );
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,
                true
        );

        assertThat(webAuthnManager.verify(webAuthnAuthenticationRequest, authenticationParameters)).failsWithin(java.time.Duration.ofSeconds(5)).withThrowableThat().havingCause().isInstanceOf(BadTopOriginException.class);
    }

    private CredentialRecord createCredentialRecord(String rpId, Challenge challenge) {

        var credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "localhost"),
                new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(AuthenticatorAttachment.CROSS_PLATFORM, true, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<>()
        );

        var response = clientPlatform.create(credentialCreationOptions);
        var registrationRequest = response.getResponse();
        AttestationObject attestationObject = attestationObjectConverter.convert(registrationRequest.getAttestationObject());
        var clientData = collectedClientDataConverter.convert(registrationRequest.getClientDataJSON());
        return new CredentialRecordImpl(attestationObject, clientData, response.getClientExtensionResults(), registrationRequest.getTransports());
    }
}
