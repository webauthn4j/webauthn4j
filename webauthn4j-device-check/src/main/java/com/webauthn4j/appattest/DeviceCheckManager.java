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

package com.webauthn4j.appattest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.appattest.converter.jackson.DeviceCheckCBORModule;
import com.webauthn4j.appattest.data.*;
import com.webauthn4j.appattest.verifier.DCAssertionDataVerifier;
import com.webauthn4j.appattest.verifier.DCAttestationDataVerifier;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.CustomCoreAuthenticationVerifier;
import com.webauthn4j.verifier.CustomCoreRegistrationVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class DeviceCheckManager {

    // ~ Instance fields
    // ================================================================================================

    private final DeviceCheckAttestationManager deviceCheckAttestationManager;
    private final DeviceCheckAssertionManager deviceCheckAssertionManager;

    public DeviceCheckManager(@NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                              @NotNull List<CustomCoreRegistrationVerifier> customRegistrationValidators,
                              @NotNull List<CustomCoreAuthenticationVerifier> customAuthenticationValidators,
                              @NotNull ObjectConverter objectConverter) {

        this.deviceCheckAttestationManager = new DeviceCheckAttestationManager(
                certPathTrustworthinessVerifier,
                customRegistrationValidators,
                objectConverter);
        this.deviceCheckAssertionManager = new DeviceCheckAssertionManager(
                customAuthenticationValidators,
                objectConverter);
    }

    public DeviceCheckManager(@NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                              @NotNull List<CustomCoreRegistrationVerifier> customRegistrationValidators,
                              @NotNull List<CustomCoreAuthenticationVerifier> customAuthenticationValidators) {
        this(
                certPathTrustworthinessVerifier,
                customRegistrationValidators,
                customAuthenticationValidators,
                createObjectConverter()
        );
    }

    public DeviceCheckManager(@NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                              @NotNull ObjectConverter objectConverter) {
        this(
                certPathTrustworthinessVerifier,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    public DeviceCheckManager(@NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier) {
        this(
                certPathTrustworthinessVerifier,
                new ArrayList<>(),
                new ArrayList<>()
        );
    }

    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link DeviceCheckManager} with non strict configuration
     *
     * @return configured {@link DeviceCheckManager}
     */
    public static @NotNull DeviceCheckManager createNonStrictDeviceCheckManager() {
        ObjectMapper jsonMapper = new ObjectMapper();
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerModule(new DeviceCheckCBORModule());
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, cborMapper);
        return createNonStrictDeviceCheckManager(objectConverter);
    }

    /**
     * Creates {@link DeviceCheckManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link DeviceCheckManager}
     */
    public static @NotNull DeviceCheckManager createNonStrictDeviceCheckManager(@NotNull ObjectConverter objectConverter) {
        return new DeviceCheckManager(
                new NullCertPathTrustworthinessVerifier(),
                objectConverter
        );
    }

    /**
     * Create {@link ObjectConverter} instance with {@link DeviceCheckCBORModule}
     *
     * @return {@link ObjectConverter} instance with {@link DeviceCheckCBORModule}
     */
    public static @NotNull ObjectConverter createObjectConverter() {
        ObjectMapper jsonMapper = new ObjectMapper();
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerModule(new DeviceCheckCBORModule());
        return new ObjectConverter(jsonMapper, cborMapper);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAttestationData parse(@NotNull DCAttestationRequest dcAttestationRequest) throws DataConversionException {
        return this.deviceCheckAttestationManager.parse(dcAttestationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAttestationData validate(@NotNull DCAttestationRequest dcAttestationRequest, @NotNull DCAttestationParameters dcAttestationParameters) throws DataConversionException, VerificationException {
        return this.deviceCheckAttestationManager.validate(dcAttestationRequest, dcAttestationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAttestationData validate(@NotNull DCAttestationData dcAttestationData, @NotNull DCAttestationParameters dcAttestationParameters) throws VerificationException {
        return this.deviceCheckAttestationManager.validate(dcAttestationData, dcAttestationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAssertionData parse(@NotNull DCAssertionRequest dcAssertionRequest) throws DataConversionException {
        return this.deviceCheckAssertionManager.parse(dcAssertionRequest);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAssertionData validate(@NotNull DCAssertionRequest dcAssertionRequest, @NotNull DCAssertionParameters dcAssertionParameters) throws DataConversionException, VerificationException {
        return this.deviceCheckAssertionManager.verify(dcAssertionRequest, dcAssertionParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAssertionData validate(@NotNull DCAssertionData dcAssertionData, @NotNull DCAssertionParameters dcAssertionParameters) throws VerificationException {
        return this.deviceCheckAssertionManager.verify(dcAssertionData, dcAssertionParameters);
    }

    public @NotNull DCAttestationDataVerifier getAttestationDataValidator() {
        return this.deviceCheckAttestationManager.getDCAttestationDataValidator();
    }

    public @NotNull DCAssertionDataVerifier getAssertionDataValidator() {
        return this.deviceCheckAssertionManager.getDCAssertionDataValidator();
    }

}
