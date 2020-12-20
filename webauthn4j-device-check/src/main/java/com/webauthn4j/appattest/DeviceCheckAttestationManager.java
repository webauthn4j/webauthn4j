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

import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.appattest.data.DCAttestationParameters;
import com.webauthn4j.appattest.data.DCAttestationRequest;
import com.webauthn4j.appattest.validator.DCAttestationDataValidator;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.CustomCoreRegistrationValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.List;

public class DeviceCheckAttestationManager {

    // ~ Instance fields
    // ================================================================================================

    private final AttestationObjectConverter attestationObjectConverter;
    private final DCAttestationDataValidator dcAttestationDataValidator;

    public DeviceCheckAttestationManager(
            @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            @NonNull List<CustomCoreRegistrationValidator> customRegistrationValidators,
            @NonNull ObjectConverter objectConverter) {
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        dcAttestationDataValidator = new DCAttestationDataValidator(
                certPathTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);
        attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    }

    @SuppressWarnings("java:S1130")
    public @NonNull DCAttestationData parse(@NonNull DCAttestationRequest dcAttestationRequest) throws DataConversionException {
        AssertUtil.notNull(dcAttestationRequest, "dcAttestationRequest must not be null");

        byte[] keyId = dcAttestationRequest.getKeyId();
        byte[] attestationObjectBytes = dcAttestationRequest.getAttestationObject();
        byte[] clientDataHash = dcAttestationRequest.getClientDataHash();

        AttestationObject attestationObject = attestationObjectBytes == null ? null : attestationObjectConverter.convert(attestationObjectBytes);

        return new DCAttestationData(
                keyId,
                attestationObject,
                attestationObjectBytes,
                clientDataHash
        );
    }

    @SuppressWarnings("squid:S1130")
    public @NonNull DCAttestationData validate(@NonNull DCAttestationRequest dcAttestationRequest, @NonNull DCAttestationParameters dcAttestationParameters) throws DataConversionException, ValidationException {
        DCAttestationData dcAttestationData = parse(dcAttestationRequest);
        return validate(dcAttestationData, dcAttestationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NonNull DCAttestationData validate(@NonNull DCAttestationData dcAttestationData, @NonNull DCAttestationParameters dcAttestationParameters) throws ValidationException {
        getDCAttestationDataValidator().validate(dcAttestationData, dcAttestationParameters);
        return dcAttestationData;
    }

    public @NonNull DCAttestationDataValidator getDCAttestationDataValidator() {
        return dcAttestationDataValidator;
    }
}
