package com.webauthn4j.spc.async;

import com.webauthn4j.async.WebAuthnAuthenticationAsyncManager;
import com.webauthn4j.async.WebAuthnRegistrationAsyncManager;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.AttestationStatementAsyncVerifier;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.SPCRegistrationParameters;
import com.webauthn4j.spc.async.verifier.SPCAuthenticationAsyncVerifier;
import com.webauthn4j.spc.async.verifier.SPCRegistrationAsyncVerifier;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.concurrent.CompletionStage;

public class SPCAsyncManager {

    private static final ClientDataType PAYMENT_GET = ClientDataType.create("payment.get");

    private final WebAuthnRegistrationAsyncManager registrationManager;
    private final WebAuthnAuthenticationAsyncManager authenticationManager;

    public SPCAsyncManager(
            @NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
            @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
            @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
            @NotNull ObjectConverter objectConverter) {
        this.registrationManager = new WebAuthnRegistrationAsyncManager(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                List.of(new SPCRegistrationAsyncVerifier()),
                objectConverter
        );
        this.authenticationManager = new WebAuthnAuthenticationAsyncManager(
                List.of(new SPCAuthenticationAsyncVerifier()),
                objectConverter
        );
        this.authenticationManager.getAuthenticationDataAsyncVerifier()
                .setExpectedClientDataType(PAYMENT_GET);
    }

    public SPCAsyncManager(@NotNull ObjectConverter objectConverter) {
        this(
                List.of(new NoneAttestationStatementAsyncVerifier()),
                new NullCertPathTrustworthinessAsyncVerifier(),
                new NullSelfAttestationTrustworthinessAsyncVerifier(),
                objectConverter
        );
    }

    public SPCAsyncManager() {
        this(SPCManager.createObjectConverter());
    }

    public @NotNull CompletionStage<RegistrationData> parse(
            @NotNull RegistrationRequest registrationRequest) {
        return registrationManager.parse(registrationRequest);
    }

    public @NotNull CompletionStage<AuthenticationData> parse(
            @NotNull AuthenticationRequest authenticationRequest) {
        return authenticationManager.parse(authenticationRequest);
    }

    public @NotNull CompletionStage<RegistrationData> verify(
            @NotNull RegistrationData registrationData,
            @NotNull SPCRegistrationParameters registrationParameters) {
        return registrationManager.verify(registrationData, registrationParameters);
    }

    public @NotNull CompletionStage<AuthenticationData> verify(
            @NotNull AuthenticationData authenticationData,
            @NotNull SPCAuthenticationParameters authenticationParameters) {
        return authenticationManager.verify(authenticationData, authenticationParameters);
    }

    public @NotNull CompletionStage<RegistrationData> verify(
            @NotNull RegistrationRequest registrationRequest,
            @NotNull SPCRegistrationParameters registrationParameters) {
        return registrationManager.parse(registrationRequest)
                .thenCompose(data -> verify(data, registrationParameters));
    }

    public @NotNull CompletionStage<AuthenticationData> verify(
            @NotNull AuthenticationRequest authenticationRequest,
            @NotNull SPCAuthenticationParameters authenticationParameters) {
        return authenticationManager.parse(authenticationRequest)
                .thenCompose(data -> verify(data, authenticationParameters));
    }
}
