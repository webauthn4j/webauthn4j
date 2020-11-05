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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.appattest.data.DCAssertionData;
import com.webauthn4j.appattest.data.DCAssertionParameters;
import com.webauthn4j.appattest.data.DCAssertionRequest;
import com.webauthn4j.appattest.validator.DCAssertionDataValidator;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.CustomCoreAuthenticationValidator;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.Collections;
import java.util.List;

public class DeviceCheckAssertionManager {

    // ~ Instance fields
    // ================================================================================================

    private final AuthenticatorDataConverter authenticatorDataConverter;

    private final DCAssertionDataValidator dcAssertionDataValidator;
    private final CborConverter cborConverter;

    public DeviceCheckAssertionManager(List<CustomCoreAuthenticationValidator> customAuthenticationValidators, ObjectConverter objectConverter) {
        AssertUtil.notNull(customAuthenticationValidators, "customAuthenticationValidators must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        dcAssertionDataValidator = new DCAssertionDataValidator(customAuthenticationValidators);
        authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        cborConverter = objectConverter.getCborConverter();
    }

    public DeviceCheckAssertionManager(List<CustomCoreAuthenticationValidator> customAuthenticationValidators) {
        this(customAuthenticationValidators, new ObjectConverter());
    }

    public DeviceCheckAssertionManager() {
        this(Collections.emptyList(), new ObjectConverter());
    }

    @SuppressWarnings("squid:S1130")
    public DCAssertionData parse(DCAssertionRequest dcAssertionRequest) throws DataConversionException {

        byte[] credentialId = dcAssertionRequest.getKeyId();
        DCAssertion assertion = cborConverter.readValue(dcAssertionRequest.getAssertion(), DCAssertion.class);
        byte[] authenticatorDataBytes = assertion.getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);
        byte[] clientDataHash = dcAssertionRequest.getClientDataHash();
        byte[] signature = assertion.getSignature();

        return new DCAssertionData(
                credentialId,
                authenticatorData,
                authenticatorDataBytes,
                clientDataHash,
                signature
        );

    }

    @SuppressWarnings("squid:S1130")
    public DCAssertionData validate(DCAssertionRequest dcAssertionRequest, DCAssertionParameters dcAssertionParameters) throws DataConversionException, ValidationException {
        DCAssertionData dcAssertionData = parse(dcAssertionRequest);
        return validate(dcAssertionData, dcAssertionParameters);
    }

    @SuppressWarnings("squid:S1130")
    public DCAssertionData validate(DCAssertionData dcAssertionData, DCAssertionParameters dcAssertionParameters) throws ValidationException {
        getDCAssertionDataValidator().validate(dcAssertionData, dcAssertionParameters);
        return dcAssertionData;
    }

    public DCAssertionDataValidator getDCAssertionDataValidator() {
        return dcAssertionDataValidator;
    }

    static class DCAssertion {

        private byte[] signature;
        private byte[] authenticatorData;

        @JsonCreator
        public DCAssertion(
                @JsonProperty("signature") byte[] signature,
                @JsonProperty("authenticatorData") byte[] authenticatorData) {
            this.signature = signature;
            this.authenticatorData = authenticatorData;
        }

        @JsonGetter("signature")
        public byte[] getSignature() {
            return signature;
        }

        @JsonGetter("authenticatorData")
        public byte[] getAuthenticatorData() {
            return authenticatorData;
        }

    }

}
