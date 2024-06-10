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

import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.AuthenticationDataVerifier;
import com.webauthn4j.verifier.CustomAuthenticationVerifier;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

public class WebAuthnAuthenticationManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnAuthenticationManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final AuthenticationDataVerifier authenticationDataVerifier;

    public WebAuthnAuthenticationManager(
            @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(customAuthenticationVerifiers, "customAuthenticationVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        authenticationDataVerifier = new AuthenticationDataVerifier(customAuthenticationVerifiers);

        collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
    }

    public WebAuthnAuthenticationManager(
            @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers) {
        this(customAuthenticationVerifiers, new ObjectConverter());
    }

    public WebAuthnAuthenticationManager() {
        this(Collections.emptyList(), new ObjectConverter());
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull AuthenticationData parse(@NotNull AuthenticationRequest authenticationRequest) throws DataConversionException {
        AssertUtil.notNull(authenticationRequest, "authenticationRequest must not be null");

        logger.trace("Parse: {}", authenticationRequest);

        byte[] credentialId = authenticationRequest.getCredentialId();
        byte[] signature = authenticationRequest.getSignature();
        byte[] userHandle = authenticationRequest.getUserHandle();
        byte[] clientDataBytes = authenticationRequest.getClientDataJSON();
        CollectedClientData collectedClientData =
                clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);
        byte[] authenticatorDataBytes = authenticationRequest.getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData =
                authenticatorDataBytes == null ? null : authenticatorDataConverter.convert(authenticatorDataBytes);
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions =
                authenticationRequest.getClientExtensionsJSON() == null ? null : authenticationExtensionsClientOutputsConverter.convert(authenticationRequest.getClientExtensionsJSON());

        return new AuthenticationData(
                credentialId,
                userHandle,
                authenticatorData,
                authenticatorDataBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                signature
        );

    }

    @SuppressWarnings("squid:S1130")
    public @NotNull AuthenticationData verify(
            @NotNull AuthenticationRequest authenticationRequest,
            @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        AuthenticationData authenticationData = parse(authenticationRequest);
        verify(authenticationData, authenticationParameters);
        return authenticationData;
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull AuthenticationData verify(
            @NotNull AuthenticationData authenticationData,
            @NotNull AuthenticationParameters authenticationParameters) throws VerificationException {
        logger.trace("Verify: {}, {}", authenticationData, authenticationParameters);
        authenticationDataVerifier.verify(authenticationData, authenticationParameters);
        return authenticationData;
    }

    public @NotNull AuthenticationDataVerifier getAuthenticationDataVerifier() {
        return authenticationDataVerifier;
    }
}
