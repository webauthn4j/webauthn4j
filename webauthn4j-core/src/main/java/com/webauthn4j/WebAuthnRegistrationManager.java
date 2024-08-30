/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.RegistrationDataVerifier;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.apple.NullAppleAnonymousAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@SuppressWarnings("java:S6539")
public class WebAuthnRegistrationManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnRegistrationManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final RegistrationDataVerifier registrationDataVerifier;

    private final ObjectConverter objectConverter;

    public WebAuthnRegistrationManager(
            @NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
            @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
            @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
            @NotNull List<CustomRegistrationVerifier> customRegistrationVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementVerifiers, "attestationStatementVerifiers must not be null");
        AssertUtil.notNull(certPathTrustworthinessVerifier, "certPathTrustworthinessVerifier must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessVerifier, "selfAttestationTrustworthinessVerifier must not be null");
        AssertUtil.notNull(customRegistrationVerifiers, "customRegistrationVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.registrationDataVerifier = new RegistrationDataVerifier(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                customRegistrationVerifiers,
                objectConverter);


        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        this.attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        this.authenticatorTransportConverter = new AuthenticatorTransportConverter();
        this.authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
        this.objectConverter = objectConverter;
    }

    public WebAuthnRegistrationManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                                       @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                                       @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
                                       @NotNull List<CustomRegistrationVerifier> customRegistrationVerifiers) {
        this(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                customRegistrationVerifiers,
                new ObjectConverter()
        );
    }

    public WebAuthnRegistrationManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                                       @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                                       @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
                                       @NotNull ObjectConverter objectConverter) {
        this(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                Collections.emptyList(),
                objectConverter
        );
    }

    public WebAuthnRegistrationManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                                       @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                                       @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier) {
        this(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                Collections.emptyList()
        );
    }


    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnRegistrationManager} with non strict configuration
     *
     * @return configured {@link WebAuthnRegistrationManager}
     */
    public static @NotNull WebAuthnRegistrationManager createNonStrictWebAuthnRegistrationManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnRegistrationManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnManager}
     */
    public static @NotNull WebAuthnRegistrationManager createNonStrictWebAuthnRegistrationManager(@NotNull ObjectConverter objectConverter) {
        return new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementVerifier(),
                        new NullFIDOU2FAttestationStatementVerifier(),
                        new NullPackedAttestationStatementVerifier(),
                        new NullTPMAttestationStatementVerifier(),
                        new NullAndroidKeyAttestationStatementVerifier(),
                        new NullAndroidSafetyNetAttestationStatementVerifier(),
                        new NullAppleAnonymousAttestationStatementVerifier()
                ),
                new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier(),
                objectConverter
        );
    }

    @SuppressWarnings("java:S2583")
    public RegistrationData parse(String registrationResponseJSON) {
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> publicKeyCredential = objectConverter.getJsonConverter().readValue(registrationResponseJSON, new TypeReference<>() {});

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
    }

    @SuppressWarnings({"java:S2583", "squid:S1130"})
    public @NotNull RegistrationData parse(@NotNull RegistrationRequest registrationRequest) throws DataConversionException {
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

    }

    public RegistrationData verify(String registrationResponseJSON, @NotNull RegistrationParameters registrationParameters) {
        RegistrationData registrationData = parse(registrationResponseJSON);
        return verify(registrationData, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull RegistrationData verify(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        RegistrationData registrationData = parse(registrationRequest);
        return verify(registrationData, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull RegistrationData verify(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) throws VerificationException {
        logger.trace("Verify: {}, {}", registrationData, registrationParameters);
        registrationDataVerifier.verify(registrationData, registrationParameters);
        return registrationData;
    }

    public @NotNull RegistrationDataVerifier getRegistrationDataVerifier() {
        return registrationDataVerifier;
    }

}
