package com.webauthn4j.async.verifier;

import com.webauthn4j.async.WebAuthnAuthenticationAsyncManager;
import com.webauthn4j.async.WebAuthnRegistrationAsyncManager;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.converter.AttestationObjectConverter;
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
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomAsyncVerifierIntegrationTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);

    private final Origin origin = new Origin("http://example.com");
    private final String rpId = "example.com";
    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(EmulatorUtil.PACKED_AUTHENTICATOR);

    @Test
    void custom_registration_async_verifier_failure_should_propagate() {
        CustomRegistrationAsyncVerifier failingVerifier = registrationObject -> {
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new ConstraintViolationException("custom registration check failed"));
            return future;
        };

        WebAuthnRegistrationAsyncManager manager = new WebAuthnRegistrationAsyncManager(
                List.of(new NoneAttestationStatementAsyncVerifier()),
                new NullCertPathTrustworthinessAsyncVerifier(),
                new NullSelfAttestationTrustworthinessAsyncVerifier(),
                List.of(failingVerifier),
                objectConverter
        );

        Challenge challenge = new DefaultChallenge();
        var options = createCredentialCreationOptions(challenge);
        var response = clientPlatform.create(options);

        RegistrationRequest request = new RegistrationRequest(
                response.getResponse().getAttestationObject(),
                response.getResponse().getClientDataJSON()
        );

        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin).rpId(rpId).challenge(challenge).build();
        RegistrationParameters params = new RegistrationParameters(
                serverProperty, options.getPubKeyCredParams(), false, true);

        var future = manager.verify(request, params).toCompletableFuture();
        assertThat(future).isCompletedExceptionally();
        assertThatThrownBy(future::join)
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(ConstraintViolationException.class)
                .hasRootCauseMessage("custom registration check failed");
    }

    @Test
    void custom_authentication_async_verifier_failure_should_propagate() {
        CustomAuthenticationAsyncVerifier failingVerifier = authenticationObject -> {
            CompletableFuture<Void> future = new CompletableFuture<>();
            future.completeExceptionally(new ConstraintViolationException("custom authentication check failed"));
            return future;
        };

        WebAuthnAuthenticationAsyncManager manager = new WebAuthnAuthenticationAsyncManager(
                List.of(failingVerifier),
                objectConverter
        );

        Challenge challenge = new DefaultChallenge();
        CredentialRecord credentialRecord = createCredentialRecord(challenge);

        Challenge authChallenge = new DefaultChallenge();
        var publicKeyCredential = clientPlatform.get(
                createCredentialRequestOptions(authChallenge));

        AuthenticationRequest request = new AuthenticationRequest(
                publicKeyCredential.getRawId(),
                publicKeyCredential.getResponse().getAuthenticatorData(),
                publicKeyCredential.getResponse().getClientDataJSON(),
                publicKeyCredential.getResponse().getSignature()
        );

        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin).rpId(rpId).challenge(authChallenge).build();
        AuthenticationParameters params = new AuthenticationParameters(
                serverProperty, credentialRecord, null, false, true);

        var future = manager.verify(request, params).toCompletableFuture();
        assertThat(future).isCompletedExceptionally();
        assertThatThrownBy(future::join)
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(ConstraintViolationException.class)
                .hasRootCauseMessage("custom authentication check failed");
    }

    private PublicKeyCredentialCreationOptions createCredentialCreationOptions(Challenge challenge) {
        return new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "localhost"),
                new PublicKeyCredentialUserEntity(new byte[32], "user", "User"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null,
                Collections.emptyList(),
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM, true,
                        UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<>()
        );
    }

    private PublicKeyCredentialRequestOptions createCredentialRequestOptions(Challenge challenge) {
        return new PublicKeyCredentialRequestOptions(
                challenge, 0L, rpId, null,
                UserVerificationRequirement.REQUIRED, null
        );
    }

    private CredentialRecord createCredentialRecord(Challenge challenge) {
        var options = createCredentialCreationOptions(challenge);
        var response = clientPlatform.create(options);
        AttestationObject attestationObject = attestationObjectConverter.convert(response.getResponse().getAttestationObject());
        var clientData = collectedClientDataConverter.convert(response.getResponse().getClientDataJSON());
        return new CredentialRecordImpl(attestationObject, clientData, response.getClientExtensionResults(), response.getResponse().getTransports());
    }
}
