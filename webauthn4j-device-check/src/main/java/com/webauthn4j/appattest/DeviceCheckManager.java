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
import com.webauthn4j.appattest.validator.DCAssertionDataValidator;
import com.webauthn4j.appattest.validator.DCAttestationDataValidator;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.validator.CustomCoreAuthenticationValidator;
import com.webauthn4j.validator.CustomCoreRegistrationValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.ArrayList;
import java.util.List;

public class DeviceCheckManager {

    // ~ Instance fields
    // ================================================================================================

    private final DeviceCheckAttestationManager deviceCheckAttestationManager;
    private final DeviceCheckAssertionManager deviceCheckAssertionManager;

    public DeviceCheckManager(CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           List<CustomCoreRegistrationValidator> customRegistrationValidators,
                           List<CustomCoreAuthenticationValidator> customAuthenticationValidators,
                           ObjectConverter objectConverter) {

        this.deviceCheckAttestationManager = new DeviceCheckAttestationManager(
                certPathTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);
        this.deviceCheckAssertionManager = new DeviceCheckAssertionManager(
                customAuthenticationValidators,
                objectConverter);
    }

    public DeviceCheckManager(CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           List<CustomCoreRegistrationValidator> customRegistrationValidators,
                           List<CustomCoreAuthenticationValidator> customAuthenticationValidators) {
        this(
                certPathTrustworthinessValidator,
                customRegistrationValidators,
                customAuthenticationValidators,
                new ObjectConverter()
        );
    }

    public DeviceCheckManager(CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           ObjectConverter objectConverter) {
        this(
                certPathTrustworthinessValidator,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    public DeviceCheckManager(CertPathTrustworthinessValidator certPathTrustworthinessValidator) {
        this(
                certPathTrustworthinessValidator,
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
    public static DeviceCheckManager createNonStrictDeviceCheckManager() {
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
    public static DeviceCheckManager createNonStrictDeviceCheckManager(ObjectConverter objectConverter) {
        return new DeviceCheckManager(
                new NullCertPathTrustworthinessValidator(),
                objectConverter
        );
    }


    @SuppressWarnings("squid:S1130")
    public DCAttestationData parse(DCAttestationRequest dcAttestationRequest) throws DataConversionException {
        return this.deviceCheckAttestationManager.parse(dcAttestationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public DCAttestationData validate(DCAttestationRequest dcAttestationRequest, DCAttestationParameters dcAttestationParameters) throws DataConversionException, ValidationException {
        return this.deviceCheckAttestationManager.validate(dcAttestationRequest, dcAttestationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public DCAttestationData validate(DCAttestationData dcAttestationData, DCAttestationParameters dcAttestationParameters) throws ValidationException {
        return this.deviceCheckAttestationManager.validate(dcAttestationData, dcAttestationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public DCAssertionData parse(DCAssertionRequest dcAssertionRequest) throws DataConversionException {
        return this.deviceCheckAssertionManager.parse(dcAssertionRequest);
    }

    @SuppressWarnings("squid:S1130")
    public DCAssertionData validate(DCAssertionRequest dcAssertionRequest, DCAssertionParameters dcAssertionParameters) throws DataConversionException, ValidationException {
        return this.deviceCheckAssertionManager.validate(dcAssertionRequest, dcAssertionParameters);
    }

    @SuppressWarnings("squid:S1130")
    public DCAssertionData validate(DCAssertionData dcAssertionData, DCAssertionParameters dcAssertionParameters) throws ValidationException {
        return this.deviceCheckAssertionManager.validate(dcAssertionData, dcAssertionParameters);
    }


    public DCAttestationDataValidator getRegistrationDataValidator() {
        return this.deviceCheckAttestationManager.getDCAttestationDataValidator();
    }

    public DCAssertionDataValidator getAuthenticationDataValidator() {
        return this.deviceCheckAssertionManager.getDCAssertionDataValidator();
    }



}
