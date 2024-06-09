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
import com.webauthn4j.appattest.validator.DCAttestationDataVerifier;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.CustomCoreRegistrationVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.ValidationException;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DeviceCheckAttestationManager {

    // ~ Instance fields
    // ================================================================================================

    private final AttestationObjectConverter attestationObjectConverter;
    private final DCAttestationDataVerifier dcAttestationDataValidator;

    public DeviceCheckAttestationManager(
            @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
            @NotNull List<CustomCoreRegistrationVerifier> customRegistrationValidators,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(certPathTrustworthinessVerifier, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        dcAttestationDataValidator = new DCAttestationDataVerifier(
                certPathTrustworthinessVerifier,
                customRegistrationValidators,
                objectConverter);
        attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    }

    @SuppressWarnings("java:S1130")
    public @NotNull DCAttestationData parse(@NotNull DCAttestationRequest dcAttestationRequest) throws DataConversionException {
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
    public @NotNull DCAttestationData validate(@NotNull DCAttestationRequest dcAttestationRequest, @NotNull DCAttestationParameters dcAttestationParameters) throws DataConversionException, ValidationException {
        DCAttestationData dcAttestationData = parse(dcAttestationRequest);
        return validate(dcAttestationData, dcAttestationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAttestationData validate(@NotNull DCAttestationData dcAttestationData, @NotNull DCAttestationParameters dcAttestationParameters) throws ValidationException {
        getDCAttestationDataValidator().verify(dcAttestationData, dcAttestationParameters);
        return dcAttestationData;
    }

    public @NotNull DCAttestationDataVerifier getDCAttestationDataValidator() {
        return dcAttestationDataValidator;
    }
}
