package com.webauthn4j.async;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.async.verifier.AuthenticationDataAsyncVerifier;
import com.webauthn4j.async.verifier.CustomAuthenticationAsyncVerifier;
import com.webauthn4j.async.verifier.CustomRegistrationAsyncVerifier;
import com.webauthn4j.async.verifier.RegistrationDataAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.AttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.apple.NullAppleAnonymousAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.none.NoneAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.packed.NullPackedAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.tpm.NullTPMAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.async.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessAsyncVerifier;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletionStage;

public class WebAuthnAsyncManager {
    // ~ Instance fields
    // ================================================================================================

    private final WebAuthnRegistrationAsyncManager webAuthnRegistrationAsyncManager;
    private final WebAuthnAuthenticationAsyncManager webAuthnAuthenticationAsyncManager;

    public WebAuthnAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
                                @NotNull List<CustomRegistrationAsyncVerifier> customRegistrationAsyncVerifiers,
                                @NotNull List<CustomAuthenticationAsyncVerifier> customAuthenticationAsyncVerifiers,
                                @NotNull ObjectConverter objectConverter) {

        this.webAuthnRegistrationAsyncManager = new WebAuthnRegistrationAsyncManager(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                customRegistrationAsyncVerifiers,
                objectConverter);
        this.webAuthnAuthenticationAsyncManager = new WebAuthnAuthenticationAsyncManager(
                customAuthenticationAsyncVerifiers,
                objectConverter);
    }

    public WebAuthnAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
                                @NotNull List<CustomRegistrationAsyncVerifier> customRegistrationAsyncVerifiers,
                                @NotNull List<CustomAuthenticationAsyncVerifier> customAuthenticationAsyncVerifiers) {
        this(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                customRegistrationAsyncVerifiers,
                customAuthenticationAsyncVerifiers,
                new ObjectConverter()
        );
    }

    public WebAuthnAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
                                @NotNull ObjectConverter objectConverter) {
        this(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    public WebAuthnAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier) {
        this(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
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
    public static @NotNull WebAuthnAsyncManager createNonStrictWebAuthnAsyncManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnAsyncManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnManager}
     */
    public static @NotNull WebAuthnAsyncManager createNonStrictWebAuthnAsyncManager(@NotNull ObjectConverter objectConverter) {
        return new WebAuthnAsyncManager(
                Arrays.asList(
                        new NoneAttestationStatementAsyncVerifier(),
                        new NullFIDOU2FAttestationStatementAsyncVerifier(),
                        new NullPackedAttestationStatementAsyncVerifier(),
                        new NullTPMAttestationStatementAsyncVerifier(),
                        new NullAndroidKeyAttestationStatementAsyncVerifier(),
                        new NullAndroidSafetyNetAttestationStatementAsyncVerifier(),
                        new NullAppleAnonymousAttestationStatementAsyncVerifier()
                ),
                new NullCertPathTrustworthinessAsyncVerifier(),
                new NullSelfAttestationTrustworthinessAsyncVerifier(),
                objectConverter
        );
    }


    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> parse(@NotNull RegistrationRequest registrationRequest) throws DataConversionException {
        return this.webAuthnRegistrationAsyncManager.parse(registrationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnRegistrationAsyncManager.verify(registrationRequest, registrationParameters);
    }


    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) throws VerificationException {
        return this.webAuthnRegistrationAsyncManager.verify(registrationData, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> parse(@NotNull AuthenticationRequest authenticationRequest) throws DataConversionException {
        return this.webAuthnAuthenticationAsyncManager.parse(authenticationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> verify(@NotNull AuthenticationRequest authenticationRequest, @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnAuthenticationAsyncManager.verify(authenticationRequest, authenticationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> verify(@NotNull AuthenticationData authenticationData, @NotNull AuthenticationParameters authenticationParameters) throws VerificationException {
        return this.webAuthnAuthenticationAsyncManager.verify(authenticationData, authenticationParameters);
    }

    public @NotNull RegistrationDataAsyncVerifier getRegistrationDataAsyncVerifier() {
        return this.webAuthnRegistrationAsyncManager.getRegistrationDataAsyncVerifier();
    }

    public @NotNull AuthenticationDataAsyncVerifier getAuthenticationDataAsyncVerifier() {
        return this.webAuthnAuthenticationAsyncManager.getAuthenticationDataAsyncVerifier();
    }

}
