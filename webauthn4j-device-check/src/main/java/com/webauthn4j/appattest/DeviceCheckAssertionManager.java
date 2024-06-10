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

import com.webauthn4j.appattest.data.DCAssertion;
import com.webauthn4j.appattest.data.DCAssertionData;
import com.webauthn4j.appattest.data.DCAssertionParameters;
import com.webauthn4j.appattest.data.DCAssertionRequest;
import com.webauthn4j.appattest.verifier.DCAssertionDataVerifier;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.CustomCoreAuthenticationVerifier;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;

import java.util.Collections;
import java.util.List;

public class DeviceCheckAssertionManager {

    // ~ Instance fields
    // ================================================================================================

    private final AuthenticatorDataConverter authenticatorDataConverter;

    private final DCAssertionDataVerifier dcAssertionDataValidator;
    private final CborConverter cborConverter;

    public DeviceCheckAssertionManager(@NotNull List<CustomCoreAuthenticationVerifier> customAuthenticationValidators, @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(customAuthenticationValidators, "customAuthenticationValidators must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        dcAssertionDataValidator = new DCAssertionDataVerifier(customAuthenticationValidators);
        authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        cborConverter = objectConverter.getCborConverter();
    }

    public DeviceCheckAssertionManager(@NotNull List<CustomCoreAuthenticationVerifier> customAuthenticationValidators) {
        this(customAuthenticationValidators, new ObjectConverter());
    }

    public DeviceCheckAssertionManager() {
        this(Collections.emptyList(), new ObjectConverter());
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAssertionData parse(@NotNull DCAssertionRequest dcAssertionRequest) throws DataConversionException {
        AssertUtil.notNull(dcAssertionRequest, "dcAssertionRequest must not be null");

        byte[] credentialId = dcAssertionRequest.getKeyId();
        DCAssertion assertion = cborConverter.readValue(dcAssertionRequest.getAssertion(), DCAssertion.class);
        byte[] authenticatorDataBytes = assertion == null ? null : assertion.getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataBytes == null ? null : authenticatorDataConverter.convert(authenticatorDataBytes);
        byte[] clientDataHash = dcAssertionRequest.getClientDataHash();
        byte[] signature = assertion == null ? null : assertion.getSignature();

        return new DCAssertionData(
                credentialId,
                authenticatorData,
                authenticatorDataBytes,
                clientDataHash,
                signature
        );

    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAssertionData verify(@NotNull DCAssertionRequest dcAssertionRequest, @NotNull DCAssertionParameters dcAssertionParameters) throws DataConversionException, VerificationException {
        DCAssertionData dcAssertionData = parse(dcAssertionRequest);
        return verify(dcAssertionData, dcAssertionParameters);
    }

    /**
     * @deprecated renamed to `verify`
     */
    @Deprecated
    public @NotNull DCAssertionData validate(@NotNull DCAssertionRequest dcAssertionRequest, @NotNull DCAssertionParameters dcAssertionParameters) throws DataConversionException, VerificationException {
        return verify(dcAssertionRequest, dcAssertionParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull DCAssertionData verify(@NotNull DCAssertionData dcAssertionData, @NotNull DCAssertionParameters dcAssertionParameters) throws VerificationException {
        getDCAssertionDataValidator().verify(dcAssertionData, dcAssertionParameters);
        return dcAssertionData;
    }


    /**
     * @deprecated renamed to `verify`
     */
    @Deprecated
    public @NotNull DCAssertionData validate(@NotNull DCAssertionData dcAssertionData, @NotNull DCAssertionParameters dcAssertionParameters) throws VerificationException {
        return verify(dcAssertionData, dcAssertionParameters);
    }

    public @NotNull DCAssertionDataVerifier getDCAssertionDataValidator() {
        return dcAssertionDataValidator;
    }

}
