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

import java.util.Collections;
import java.util.List;

public class DeviceCheckAttestationManager {

    // ~ Instance fields
    // ================================================================================================

    private final AttestationObjectConverter attestationObjectConverter;
    private final DCAttestationDataValidator dcAttestationDataValidator;

    public DeviceCheckAttestationManager(
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            List<CustomCoreRegistrationValidator> customRegistrationValidators,
            ObjectConverter objectConverter) {
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        dcAttestationDataValidator = new DCAttestationDataValidator(
                certPathTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);
        attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    }

    @SuppressWarnings("java:S1130")
    public DCAttestationData parse(DCAttestationRequest dcAttestationRequest) throws DataConversionException {

        byte[] keyIdentifierBytes = dcAttestationRequest.getKeyIdentifier();
        byte[] attestationObjectBytes = dcAttestationRequest.getAttestationObject();
        byte[] clientDataHash= dcAttestationRequest.getClientDataHash();

        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);

        return new DCAttestationData(
                keyIdentifierBytes,
                attestationObject,
                attestationObjectBytes,
                clientDataHash,
                Collections.emptySet()
        );
    }

    @SuppressWarnings("squid:S1130")
    public DCAttestationData validate(DCAttestationRequest dcAttestationRequest, DCAttestationParameters dcAttestationParameters) throws DataConversionException, ValidationException {
        DCAttestationData dcAttestationData = parse(dcAttestationRequest);
        dcAttestationDataValidator.validate(dcAttestationData, dcAttestationParameters);
        return dcAttestationData;
    }

    @SuppressWarnings("squid:S1130")
    public DCAttestationData validate(DCAttestationData dcAttestationData, DCAttestationParameters dcAttestationParameters) throws ValidationException {
        dcAttestationDataValidator.validate(dcAttestationData, dcAttestationParameters);
        return dcAttestationData;
    }

    public DCAttestationDataValidator getDCAttestationDataValidator() {
        return dcAttestationDataValidator;
    }
}
