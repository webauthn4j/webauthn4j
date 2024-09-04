package com.webauthn4j.async;

import com.fasterxml.jackson.core.type.TypeReference;
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
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
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

public class WebAuthnRegistrationAsyncManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnRegistrationAsyncManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final RegistrationDataAsyncVerifier registrationDataAsyncVerifier;
    private final ObjectConverter objectConverter;

    public WebAuthnRegistrationAsyncManager(
            @NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
            @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
            @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
            @NotNull List<CustomRegistrationAsyncVerifier> customRegistrationAsyncVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementAsyncVerifiers, "attestationStatementAsyncVerifiers must not be null");
        AssertUtil.notNull(certPathTrustworthinessAsyncVerifier, "certPathTrustworthinessAsyncVerifier must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessAsyncVerifier, "selfAttestationTrustworthinessAsyncVerifier must not be null");
        AssertUtil.notNull(customRegistrationAsyncVerifiers, "customRegistrationAsyncVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.registrationDataAsyncVerifier = new RegistrationDataAsyncVerifier(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                customRegistrationAsyncVerifiers,
                objectConverter);


        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        this.attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        this.authenticatorTransportConverter = new AuthenticatorTransportConverter();
        this.authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
        this.objectConverter = objectConverter;
    }

    public WebAuthnRegistrationAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                            @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                            @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
                                            @NotNull List<CustomRegistrationAsyncVerifier> customRegistrationAsyncVerifiers) {
        this(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                customRegistrationAsyncVerifiers,
                new ObjectConverter()
        );
    }

    public WebAuthnRegistrationAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                            @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                            @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier,
                                            @NotNull ObjectConverter objectConverter) {
        this(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                Collections.emptyList(),
                objectConverter
        );
    }

    public WebAuthnRegistrationAsyncManager(@NotNull List<AttestationStatementAsyncVerifier> attestationStatementAsyncVerifiers,
                                            @NotNull CertPathTrustworthinessAsyncVerifier certPathTrustworthinessAsyncVerifier,
                                            @NotNull SelfAttestationTrustworthinessAsyncVerifier selfAttestationTrustworthinessAsyncVerifier) {
        this(
                attestationStatementAsyncVerifiers,
                certPathTrustworthinessAsyncVerifier,
                selfAttestationTrustworthinessAsyncVerifier,
                Collections.emptyList()
        );
    }


    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnRegistrationAsyncManager} with non strict configuration
     *
     * @return configured {@link WebAuthnRegistrationAsyncManager}
     */
    public static @NotNull WebAuthnRegistrationAsyncManager createNonStrictWebAuthnRegistrationAsyncManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnRegistrationAsyncManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnAsyncManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnAsyncManager}
     */
    public static @NotNull WebAuthnRegistrationAsyncManager createNonStrictWebAuthnRegistrationAsyncManager(@NotNull ObjectConverter objectConverter) {
        return new WebAuthnRegistrationAsyncManager(
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
    public @NotNull CompletionStage<RegistrationData> parse(String registrationResponseJSON) {
        return CompletionStageUtil
                .supply(()-> objectConverter.getJsonConverter().readValue(registrationResponseJSON, new TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>>() {}))
                .thenApply(publicKeyCredential -> {
                    byte[] attestationObjectBytes = publicKeyCredential.getResponse().getAttestationObject();
                    AttestationObject attestationObject = attestationObjectBytes == null ? null : attestationObjectConverter.convert(attestationObjectBytes);
                    byte[] clientDataBytes = publicKeyCredential.getResponse().getClientDataJSON();
                    CollectedClientData collectedClientData = clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);

                    return new RegistrationData(
                            attestationObject,
                            attestationObjectBytes,
                            collectedClientData,
                            clientDataBytes,
                            publicKeyCredential.getClientExtensionResults(),
                            publicKeyCredential.getResponse().getTransports()
                    );
                });
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

    public CompletionStage<RegistrationData> verify(String registrationResponseJSON, @NotNull RegistrationParameters registrationParameters) {
        return parse(registrationResponseJSON).thenCompose(registrationData -> verify(registrationData, registrationParameters));
    }


    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) {
        return parse(registrationRequest)
                .thenCompose(registrationData -> verify(registrationData , registrationParameters));
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<RegistrationData> verify(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) {
        logger.trace("Verify: {}, {}", registrationData, registrationParameters);
        return registrationDataAsyncVerifier.verify(registrationData, registrationParameters);
    }

    public @NotNull RegistrationDataAsyncVerifier getRegistrationDataAsyncVerifier() {
        return registrationDataAsyncVerifier;
    }

}
