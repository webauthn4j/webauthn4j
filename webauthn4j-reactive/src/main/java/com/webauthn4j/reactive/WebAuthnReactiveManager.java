package com.webauthn4j.reactive;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.reactive.verifier.AuthenticationDataReactiveVerifier;
import com.webauthn4j.reactive.verifier.CustomAuthenticationReactiveVerifier;
import com.webauthn4j.reactive.verifier.CustomRegistrationReactiveVerifier;
import com.webauthn4j.reactive.verifier.RegistrationDataReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.AttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.apple.NullAppleAnonymousAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.none.NoneAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.packed.NullPackedAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.tpm.NullTPMAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessReactiveVerifier;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletionStage;

public class WebAuthnReactiveManager {
    // ~ Instance fields
    // ================================================================================================

    private final WebAuthnRegistrationReactiveManager webAuthnRegistrationReactiveManager;
    private final WebAuthnAuthenticationReactiveManager webAuthnAuthenticationReactiveManager;

    public WebAuthnReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                           @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                           @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier,
                           @NotNull List<CustomRegistrationReactiveVerifier> customRegistrationReactiveVerifiers,
                           @NotNull List<CustomAuthenticationReactiveVerifier> customAuthenticationReactiveVerifiers,
                           @NotNull ObjectConverter objectConverter) {

        this.webAuthnRegistrationReactiveManager = new WebAuthnRegistrationReactiveManager(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                customRegistrationReactiveVerifiers,
                objectConverter);
        this.webAuthnAuthenticationReactiveManager = new WebAuthnAuthenticationReactiveManager(
                customAuthenticationReactiveVerifiers,
                objectConverter);
    }

    public WebAuthnReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                           @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                           @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier,
                           @NotNull List<CustomRegistrationReactiveVerifier> customRegistrationReactiveVerifiers,
                           @NotNull List<CustomAuthenticationReactiveVerifier> customAuthenticationReactiveVerifiers) {
        this(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                customRegistrationReactiveVerifiers,
                customAuthenticationReactiveVerifiers,
                new ObjectConverter()
        );
    }

    public WebAuthnReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                           @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                           @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier,
                           @NotNull ObjectConverter objectConverter) {
        this(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    public WebAuthnReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                           @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                           @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier) {
        this(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                new ArrayList<>(),
                new ArrayList<>()
        );
    }

    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @return configured {@link WebAuthnManager}
     */
    public static @NotNull WebAuthnReactiveManager createNonStrictWebAuthnReactiveManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnReactiveManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnManager}
     */
    public static @NotNull WebAuthnReactiveManager createNonStrictWebAuthnReactiveManager(@NotNull ObjectConverter objectConverter) {
        return new WebAuthnReactiveManager(
                Arrays.asList(
                        new NoneAttestationStatementReactiveVerifier(),
                        new NullFIDOU2FAttestationStatementReactiveVerifier(),
                        new NullPackedAttestationStatementReactiveVerifier(),
                        new NullTPMAttestationStatementReactiveVerifier(),
                        new NullAndroidKeyAttestationStatementReactiveVerifier(),
                        new NullAndroidSafetyNetAttestationStatementReactiveVerifier(),
                        new NullAppleAnonymousAttestationStatementReactiveVerifier()
                ),
                new NullCertPathTrustworthinessReactiveVerifier(),
                new NullSelfAttestationTrustworthinessReactiveVerifier(),
                objectConverter
        );
    }


    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> parse(@NotNull RegistrationRequest registrationRequest) throws DataConversionException {
        return this.webAuthnRegistrationReactiveManager.parse(registrationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnRegistrationReactiveManager.verify(registrationRequest, registrationParameters);
    }


    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) throws VerificationException {
        return this.webAuthnRegistrationReactiveManager.verify(registrationData, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> parse(@NotNull AuthenticationRequest authenticationRequest) throws DataConversionException {
        return this.webAuthnAuthenticationReactiveManager.parse(authenticationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> verify(@NotNull AuthenticationRequest authenticationRequest, @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnAuthenticationReactiveManager.verify(authenticationRequest, authenticationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> verify(@NotNull AuthenticationData authenticationData, @NotNull AuthenticationParameters authenticationParameters) throws VerificationException {
        return this.webAuthnAuthenticationReactiveManager.verify(authenticationData, authenticationParameters);
    }

    public @NotNull RegistrationDataReactiveVerifier getRegistrationDataReactiveVerifier() {
        return this.webAuthnRegistrationReactiveManager.getRegistrationDataReactiveVerifier();
    }

    public @NotNull AuthenticationDataReactiveVerifier getAuthenticationDataReactiveVerifier() {
        return this.webAuthnAuthenticationReactiveManager.getAuthenticationDataReactiveVerifier();
    }

}
