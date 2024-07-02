package com.webauthn4j.reactive;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.reactive.verifier.CustomRegistrationReactiveVerifier;
import com.webauthn4j.reactive.verifier.RegistrationDataReactiveVerifier;
import com.webauthn4j.reactive.verifier.attestation.statement.*;
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
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CompletionStageUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletionStage;

public class WebAuthnRegistrationReactiveManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnRegistrationManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final RegistrationDataReactiveVerifier registrationDataReactiveVerifier;

    public WebAuthnRegistrationReactiveManager(
            @NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
            @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
            @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier,
            @NotNull List<CustomRegistrationReactiveVerifier> customRegistrationReactiveVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementReactiveVerifiers, "attestationStatementReactiveVerifiers must not be null");
        AssertUtil.notNull(certPathTrustworthinessReactiveVerifier, "certPathTrustworthinessReactiveVerifier must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessReactiveVerifier, "selfAttestationTrustworthinessReactiveVerifier must not be null");
        AssertUtil.notNull(customRegistrationReactiveVerifiers, "customRegistrationReactiveVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        registrationDataReactiveVerifier = new RegistrationDataReactiveVerifier(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                customRegistrationReactiveVerifiers,
                objectConverter);


        collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        authenticatorTransportConverter = new AuthenticatorTransportConverter();
        authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
    }

    public WebAuthnRegistrationReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                                       @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                                       @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier,
                                       @NotNull List<CustomRegistrationReactiveVerifier> customRegistrationReactiveVerifiers) {
        this(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                customRegistrationReactiveVerifiers,
                new ObjectConverter()
        );
    }

    public WebAuthnRegistrationReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                                       @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                                       @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier,
                                       @NotNull ObjectConverter objectConverter) {
        this(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                Collections.emptyList(),
                objectConverter
        );
    }

    public WebAuthnRegistrationReactiveManager(@NotNull List<AttestationStatementReactiveVerifier> attestationStatementReactiveVerifiers,
                                       @NotNull CertPathTrustworthinessReactiveVerifier certPathTrustworthinessReactiveVerifier,
                                       @NotNull SelfAttestationTrustworthinessReactiveVerifier selfAttestationTrustworthinessReactiveVerifier) {
        this(
                attestationStatementReactiveVerifiers,
                certPathTrustworthinessReactiveVerifier,
                selfAttestationTrustworthinessReactiveVerifier,
                Collections.emptyList()
        );
    }


    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnRegistrationReactiveManager} with non strict configuration
     *
     * @return configured {@link WebAuthnRegistrationReactiveManager}
     */
    public static @NotNull WebAuthnRegistrationReactiveManager createNonStrictWebAuthnRegistrationReactiveManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnRegistrationReactiveManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnReactiveManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnReactiveManager}
     */
    public static @NotNull WebAuthnRegistrationReactiveManager createNonStrictWebAuthnRegistrationReactiveManager(@NotNull ObjectConverter objectConverter) {
        return new WebAuthnRegistrationReactiveManager(
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
    public @NotNull CompletionStage<RegistrationData> parse(@NotNull RegistrationRequest registrationRequest) {
        return CompletionStageUtil.supply(()->{
            AssertUtil.notNull(registrationRequest, "registrationRequest must not be null");

            byte[] clientDataBytes = registrationRequest.getClientDataJSON();
            byte[] attestationObjectBytes = registrationRequest.getAttestationObject();

            logger.trace("Parse: {}", registrationRequest);

            CollectedClientData collectedClientData =
                    clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);
            AttestationObject attestationObject =
                    attestationObjectBytes == null ? null : attestationObjectConverter.convert(attestationObjectBytes);
            Set<AuthenticatorTransport> transports =
                    registrationRequest.getTransports() == null ? null : authenticatorTransportConverter.convertSet(registrationRequest.getTransports());
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions =
                    registrationRequest.getClientExtensionsJSON() == null ? null : authenticationExtensionsClientOutputsConverter.convert(registrationRequest.getClientExtensionsJSON());

            return new RegistrationData(
                    attestationObject,
                    attestationObjectBytes,
                    collectedClientData,
                    clientDataBytes,
                    clientExtensions,
                    transports
            );
        });
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) {
        return parse(registrationRequest)
                .thenCompose(registrationData -> verify(registrationData , registrationParameters));
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) {
        logger.trace("Verify: {}, {}", registrationData, registrationParameters);
        return registrationDataReactiveVerifier.verify(registrationData, registrationParameters);
    }

    public @NotNull RegistrationDataReactiveVerifier getRegistrationDataReactiveVerifier() {
        return registrationDataReactiveVerifier;
    }

}
