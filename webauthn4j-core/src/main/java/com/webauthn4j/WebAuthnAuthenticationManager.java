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
import com.webauthn4j.data.*;
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
import tools.jackson.core.type.TypeReference;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/**
 * Manager class for WebAuthn authentication operations.
 * This class provides methods for parsing and verifying WebAuthn authentication data.
 * It handles the authentication phase of the WebAuthn authentication process, including
 * signature verification and custom authentication verification.
 */
@SuppressWarnings("java:S6539")
public class WebAuthnAuthenticationManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnAuthenticationManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final AuthenticationDataVerifier authenticationDataVerifier;

    private final ObjectConverter objectConverter;

    /**
     * Constructor for WebAuthnAuthenticationManager with custom verifiers and object converter
     *
     * @param customAuthenticationVerifiers list of custom authentication verifiers
     * @param objectConverter converter for object serialization/deserialization
     */
    public WebAuthnAuthenticationManager(
            @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(customAuthenticationVerifiers, "customAuthenticationVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.authenticationDataVerifier = new AuthenticationDataVerifier(customAuthenticationVerifiers);

        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        this.authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        this.authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

        this.objectConverter = objectConverter;
    }

    /**
     * Constructor for WebAuthnAuthenticationManager with custom verifiers
     *
     * @param customAuthenticationVerifiers list of custom authentication verifiers
     */
    public WebAuthnAuthenticationManager(
            @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers) {
        this(customAuthenticationVerifiers, new ObjectConverter());
    }

    /**
     * Default constructor for WebAuthnAuthenticationManager
     * Creates an instance with empty custom authentication verifiers and default object converter
     */
    public WebAuthnAuthenticationManager() {
        this(Collections.emptyList(), new ObjectConverter());
    }


    /**
     * Parses a WebAuthn authentication response JSON string
     *
     * @param authenticationResponseJSON the authentication response in JSON format
     * @return the parsed authentication data
     */
    public @NotNull AuthenticationData parse(@NotNull String authenticationResponseJSON) {
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> publicKeyCredential = objectConverter.getJsonConverter().readValue(authenticationResponseJSON, new TypeReference<>() {});
        return toAuthenticationData(publicKeyCredential);
    }

    /**
     * Parses a WebAuthn authentication response JSON from an input stream
     *
     * @param authenticationResponseJSON the authentication response in JSON format as an input stream
     * @return the parsed authentication data
     */
    public @NotNull AuthenticationData parse(@NotNull InputStream authenticationResponseJSON) {
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> publicKeyCredential = objectConverter.getJsonConverter().readValue(authenticationResponseJSON, new TypeReference<>() {});
        return toAuthenticationData(publicKeyCredential);
    }

    @SuppressWarnings("java:S2583")
    private @NotNull AuthenticationData toAuthenticationData(@NotNull PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> publicKeyCredential){
        byte[] credentialId = publicKeyCredential.getRawId();
        byte[] userHandle = publicKeyCredential.getResponse().getUserHandle();

        byte[] clientDataBytes = publicKeyCredential.getResponse().getClientDataJSON();
        CollectedClientData collectedClientData = clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);

        byte[] authenticatorDataBytes = publicKeyCredential.getResponse().getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataBytes == null ? null : authenticatorDataConverter.convert(authenticatorDataBytes);

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions = publicKeyCredential.getClientExtensionResults();

        byte[] signature = publicKeyCredential.getResponse().getSignature();

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

    /**
     * Parses a WebAuthn authentication request
     *
     * @param authenticationRequest the authentication request to parse
     * @return the parsed authentication data
     * @throws DataConversionException if data conversion fails
     */
    @SuppressWarnings({"squid:S1130", "java:S2583"})
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

    /**
     * Verifies a WebAuthn authentication response JSON string
     *
     * @param authenticationResponseJSON the authentication response in JSON format
     * @param authenticationParameters the parameters for authentication verification
     * @return the verified authentication data
     * @throws DataConversionException if data conversion fails
     * @throws VerificationException if verification fails
     */
    public @NotNull AuthenticationData verify(
            @NotNull String authenticationResponseJSON,
            @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        AuthenticationData authenticationData = parse(authenticationResponseJSON);
        return verify(authenticationData, authenticationParameters);
    }

    /**
     * Verifies a WebAuthn authentication response JSON from an input stream
     *
     * @param authenticationResponseJSON the authentication response in JSON format as an input stream
     * @param authenticationParameters the parameters for authentication verification
     * @return the verified authentication data
     * @throws DataConversionException if data conversion fails
     * @throws VerificationException if verification fails
     */
    public @NotNull AuthenticationData verify(
            @NotNull InputStream authenticationResponseJSON,
            @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        AuthenticationData authenticationData = parse(authenticationResponseJSON);
        return verify(authenticationData, authenticationParameters);
    }

    /**
     * Verifies a WebAuthn authentication request
     *
     * @param authenticationRequest the authentication request to verify
     * @param authenticationParameters the parameters for authentication verification
     * @return the verified authentication data
     * @throws DataConversionException if data conversion fails
     * @throws VerificationException if verification fails
     */
    @SuppressWarnings("squid:S1130")
    public @NotNull AuthenticationData verify(
            @NotNull AuthenticationRequest authenticationRequest,
            @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        AuthenticationData authenticationData = parse(authenticationRequest);
        verify(authenticationData, authenticationParameters);
        return authenticationData;
    }

    /**
     * Verifies WebAuthn authentication data
     *
     * @param authenticationData the authentication data to verify
     * @param authenticationParameters the parameters for authentication verification
     * @return the verified authentication data
     * @throws VerificationException if verification fails
     */
    @SuppressWarnings("squid:S1130")
    public @NotNull AuthenticationData verify(
            @NotNull AuthenticationData authenticationData,
            @NotNull AuthenticationParameters authenticationParameters) throws VerificationException {
        logger.trace("Verify: {}, {}", authenticationData, authenticationParameters);
        authenticationDataVerifier.verify(authenticationData, authenticationParameters);
        return authenticationData;
    }

    /**
     * Gets the authentication data verifier
     *
     * @return the authentication data verifier
     */
    public @NotNull AuthenticationDataVerifier getAuthenticationDataVerifier() {
        return authenticationDataVerifier;
    }
}
