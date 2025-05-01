/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.verifier.AuthenticationDataVerifier;
import com.webauthn4j.verifier.CustomAuthenticationVerifier;
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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Manager class for WebAuthn operations.
 * 
 * This class provides a unified interface for WebAuthn registration and authentication operations.
 * It delegates registration operations to {@link WebAuthnRegistrationManager} and authentication
 * operations to {@link WebAuthnAuthenticationManager}.
 * 
 * WebAuthnManager supports parsing and verification of WebAuthn registration and authentication
 * requests and responses in various formats (JSON string, InputStream, or object).
 * 
 * Factory methods are provided to create instances with a non-strict configuration
 * that is more lenient in its verification requirements.
 */
@SuppressWarnings("java:S6539")
public class WebAuthnManager {

    // ~ Instance fields
    // ================================================================================================

    private final WebAuthnRegistrationManager webAuthnRegistrationManager;
    private final WebAuthnAuthenticationManager webAuthnAuthenticationManager;

    /**
     * Constructor for WebAuthnManager with full customization options
     *
     * @param attestationStatementVerifiers list of attestation statement verifiers
     * @param certPathTrustworthinessVerifier verifier for certification path trustworthiness
     * @param selfAttestationTrustworthinessVerifier verifier for self attestation trustworthiness
     * @param customRegistrationVerifiers list of custom registration verifiers
     * @param customAuthenticationVerifiers list of custom authentication verifiers
     * @param objectConverter converter for object serialization/deserialization
     */
    public WebAuthnManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                           @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                           @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
                           @NotNull List<CustomRegistrationVerifier> customRegistrationVerifiers,
                           @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers,
                           @NotNull ObjectConverter objectConverter) {

        this.webAuthnRegistrationManager = new WebAuthnRegistrationManager(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                customRegistrationVerifiers,
                objectConverter);
        this.webAuthnAuthenticationManager = new WebAuthnAuthenticationManager(
                customAuthenticationVerifiers,
                objectConverter);
    }

    /**
     * Constructor for WebAuthnManager with custom verifiers
     *
     * @param attestationStatementVerifiers list of attestation statement verifiers
     * @param certPathTrustworthinessVerifier verifier for certification path trustworthiness
     * @param selfAttestationTrustworthinessVerifier verifier for self attestation trustworthiness
     * @param customRegistrationVerifiers list of custom registration verifiers
     * @param customAuthenticationVerifiers list of custom authentication verifiers
     */
    public WebAuthnManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                           @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                           @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
                           @NotNull List<CustomRegistrationVerifier> customRegistrationVerifiers,
                           @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers) {
        this(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                customRegistrationVerifiers,
                customAuthenticationVerifiers,
                new ObjectConverter()
        );
    }

    /**
     * Constructor for WebAuthnManager with custom verifiers and object converter
     *
     * @param attestationStatementVerifiers list of attestation statement verifiers
     * @param certPathTrustworthinessVerifier verifier for certification path trustworthiness
     * @param selfAttestationTrustworthinessVerifier verifier for self attestation trustworthiness
     * @param objectConverter converter for object serialization/deserialization
     */
    public WebAuthnManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                           @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                           @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
                           @NotNull ObjectConverter objectConverter) {
        this(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    /**
     * Constructor for WebAuthnManager with custom verifiers and default object converter
     *
     * @param attestationStatementVerifiers list of attestation statement verifiers
     * @param certPathTrustworthinessVerifier verifier for certification path trustworthiness
     * @param selfAttestationTrustworthinessVerifier verifier for self attestation trustworthiness
     */
    public WebAuthnManager(@NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
                           @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
                           @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier) {
        this(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                new ArrayList<>(),
                new ArrayList<>()
        );
    }

    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @return configured {@link WebAuthnManager}
     */
    public static @NotNull WebAuthnManager createNonStrictWebAuthnManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnManager}
     */
    public static @NotNull WebAuthnManager createNonStrictWebAuthnManager(@NotNull ObjectConverter objectConverter) {
        return new WebAuthnManager(
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

    /**
     * Parses a WebAuthn registration response JSON string
     *
     * @param registrationResponseJSON the registration response in JSON format
     * @return the parsed registration data
     */
    public @NotNull RegistrationData parseRegistrationResponseJSON(@NotNull String registrationResponseJSON){
        return this.webAuthnRegistrationManager.parse(registrationResponseJSON);
    }

    /**
     * Parses a WebAuthn registration response JSON from an input stream
     *
     * @param registrationResponseJSON the registration response in JSON format as an input stream
     * @return the parsed registration data
     */
    public @NotNull RegistrationData parseRegistrationResponseJSON(@NotNull InputStream registrationResponseJSON){
        return this.webAuthnRegistrationManager.parse(registrationResponseJSON);
    }

    /**
     * Parses a WebAuthn registration request
     *
     * @param registrationRequest the registration request to parse
     * @return the parsed registration data
     * @throws DataConversionException if data conversion fails
     */
    @SuppressWarnings("squid:S1130")
    public @NotNull RegistrationData parse(@NotNull RegistrationRequest registrationRequest) throws DataConversionException {
        return this.webAuthnRegistrationManager.parse(registrationRequest);
    }

    /**
     * Verifies a WebAuthn registration response JSON string
     *
     * @param registrationResponseJSON the registration response in JSON format
     * @param registrationParameters the parameters for registration verification
     * @return the verified registration data
     * @throws DataConversionException if data conversion fails
     * @throws VerificationException if verification fails
     */
    public @NotNull RegistrationData verifyRegistrationResponseJSON(@NotNull String registrationResponseJSON, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnRegistrationManager.verify(registrationResponseJSON, registrationParameters);
    }

    /**
     * Verifies a WebAuthn registration response JSON from an input stream
     *
     * @param registrationResponseJSON the registration response in JSON format as an input stream
     * @param registrationParameters the parameters for registration verification
     * @return the verified registration data
     * @throws DataConversionException if data conversion fails
     * @throws VerificationException if verification fails
     */
    public @NotNull RegistrationData verifyRegistrationResponseJSON(@NotNull InputStream registrationResponseJSON, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnRegistrationManager.verify(registrationResponseJSON, registrationParameters);
    }

    /**
     * Verifies a WebAuthn registration request
     *
     * @param registrationRequest the registration request to verify
     * @param registrationParameters the parameters for registration verification
     * @return the verified registration data
     * @throws DataConversionException if data conversion fails
     * @throws VerificationException if verification fails
     */
    @SuppressWarnings("squid:S1130")
    public @NotNull RegistrationData verify(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnRegistrationManager.verify(registrationRequest, registrationParameters);
    }

    /**
     * @deprecated renamed to 'verify`
     */
    @Deprecated
    public @NotNull RegistrationData validate(@NotNull RegistrationRequest registrationRequest, @NotNull RegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        return verify(registrationRequest, registrationParameters);
    }

    /**
     * Verifies WebAuthn registration data
     *
     * @param registrationData the registration data to verify
     * @param registrationParameters the parameters for registration verification
     * @return the verified registration data
     * @throws VerificationException if verification fails
     */
    @SuppressWarnings("squid:S1130")
    public @NotNull RegistrationData verify(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) throws VerificationException {
        return this.webAuthnRegistrationManager.verify(registrationData, registrationParameters);
    }

    /**
     * @deprecated renamed to 'verify`
     */
    @Deprecated
    public @NotNull RegistrationData validate(@NotNull RegistrationData registrationData, @NotNull RegistrationParameters registrationParameters) throws VerificationException {
        return verify(registrationData, registrationParameters);
    }

    /**
     * Parses a WebAuthn authentication response JSON string
     *
     * @param authenticationResponseJSON the authentication response in JSON format
     * @return the parsed authentication data
     * @throws DataConversionException if data conversion fails
     */
    public @NotNull AuthenticationData parseAuthenticationResponseJSON(@NotNull String authenticationResponseJSON) throws DataConversionException {
        return this.webAuthnAuthenticationManager.parse(authenticationResponseJSON);
    }

    /**
     * Parses a WebAuthn authentication response JSON from an input stream
     *
     * @param authenticationResponseJSON the authentication response in JSON format as an input stream
     * @return the parsed authentication data
     * @throws DataConversionException if data conversion fails
     */
    public @NotNull AuthenticationData parseAuthenticationResponseJSON(@NotNull InputStream authenticationResponseJSON) throws DataConversionException {
        return this.webAuthnAuthenticationManager.parse(authenticationResponseJSON);
    }

    /**
     * Parses a WebAuthn authentication request
     *
     * @param authenticationRequest the authentication request to parse
     * @return the parsed authentication data
     * @throws DataConversionException if data conversion fails
     */
    @SuppressWarnings("squid:S1130")
    public @NotNull AuthenticationData parse(@NotNull AuthenticationRequest authenticationRequest) throws DataConversionException {
        return this.webAuthnAuthenticationManager.parse(authenticationRequest);
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
    public @NotNull AuthenticationData verifyAuthenticationResponseJSON(@NotNull String authenticationResponseJSON, @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnAuthenticationManager.verify(authenticationResponseJSON, authenticationParameters);
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
    public @NotNull AuthenticationData verifyAuthenticationResponseJSON(@NotNull InputStream authenticationResponseJSON, @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnAuthenticationManager.verify(authenticationResponseJSON, authenticationParameters);
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
    public @NotNull AuthenticationData verify(@NotNull AuthenticationRequest authenticationRequest, @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return this.webAuthnAuthenticationManager.verify(authenticationRequest, authenticationParameters);
    }

    /**
     * @deprecated renamed to 'verify`
     */
    @Deprecated
    public @NotNull AuthenticationData validate(@NotNull AuthenticationRequest authenticationRequest, @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return verify(authenticationRequest, authenticationParameters);
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
    public @NotNull AuthenticationData verify(@NotNull AuthenticationData authenticationData, @NotNull AuthenticationParameters authenticationParameters) throws VerificationException {
        return this.webAuthnAuthenticationManager.verify(authenticationData, authenticationParameters);
    }

    /**
     * @deprecated renamed to 'verify`
     */
    @Deprecated
    public @NotNull AuthenticationData validate(@NotNull AuthenticationData authenticationData, @NotNull AuthenticationParameters authenticationParameters) throws VerificationException {
        return verify(authenticationData, authenticationParameters);
    }

    /**
     * Gets the registration data verifier
     *
     * @return the registration data verifier
     */
    public @NotNull RegistrationDataVerifier getRegistrationDataVerifier() {
        return this.webAuthnRegistrationManager.getRegistrationDataVerifier();
    }

    /**
     * Gets the authentication data verifier
     *
     * @return the authentication data verifier
     */
    public @NotNull AuthenticationDataVerifier getAuthenticationDataVerifier() {
        return this.webAuthnAuthenticationManager.getAuthenticationDataVerifier();
    }
}
