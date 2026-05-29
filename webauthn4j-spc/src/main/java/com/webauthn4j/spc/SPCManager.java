package com.webauthn4j.spc;

import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.spc.converter.jackson.SPCJSONModule;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.SPCRegistrationParameters;
import com.webauthn4j.spc.verifier.SPCAuthenticationVerifier;
import com.webauthn4j.spc.verifier.SPCRegistrationVerifier;
import com.webauthn4j.verifier.CustomAuthenticationVerifier;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.util.ArrayList;
import java.util.List;

public class SPCManager {

    private static final ClientDataType PAYMENT_GET = ClientDataType.create("payment.get");

    private final WebAuthnRegistrationManager registrationManager;
    private final WebAuthnAuthenticationManager authenticationManager;

    public SPCManager(
            @NotNull List<AttestationStatementVerifier> attestationStatementVerifiers,
            @NotNull CertPathTrustworthinessVerifier certPathTrustworthinessVerifier,
            @NotNull SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier,
            @NotNull List<CustomRegistrationVerifier> customRegistrationVerifiers,
            @NotNull List<CustomAuthenticationVerifier> customAuthenticationVerifiers,
            @NotNull ObjectConverter objectConverter) {
        List<CustomRegistrationVerifier> registrationVerifiers = new ArrayList<>();
        registrationVerifiers.add(new SPCRegistrationVerifier());
        registrationVerifiers.addAll(customRegistrationVerifiers);

        List<CustomAuthenticationVerifier> authenticationVerifiers = new ArrayList<>();
        authenticationVerifiers.add(new SPCAuthenticationVerifier());
        authenticationVerifiers.addAll(customAuthenticationVerifiers);

        this.registrationManager = new WebAuthnRegistrationManager(
                attestationStatementVerifiers,
                certPathTrustworthinessVerifier,
                selfAttestationTrustworthinessVerifier,
                registrationVerifiers,
                objectConverter
        );
        this.authenticationManager = new WebAuthnAuthenticationManager(
                authenticationVerifiers,
                objectConverter
        );
        this.authenticationManager.getAuthenticationDataVerifier()
                .setExpectedClientDataType(PAYMENT_GET);
    }

    public SPCManager(@NotNull ObjectConverter objectConverter) {
        this(
                List.of(new NoneAttestationStatementVerifier()),
                new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier(),
                List.of(),
                List.of(),
                objectConverter
        );
    }

    public SPCManager() {
        this(createObjectConverter());
    }

    /**
     * Create {@link ObjectConverter} instance with {@link SPCJSONModule}
     *
     * @return {@link ObjectConverter} instance with {@link SPCJSONModule}
     */
    public static @NotNull ObjectConverter createObjectConverter() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonMapper jsonMapper = objectConverter.getJsonMapper().rebuild()
                .addModule(new SPCJSONModule(objectConverter))
                .build();
        return new ObjectConverter(jsonMapper, objectConverter.getCborMapper());
    }

    public @NotNull RegistrationData parse(
            @NotNull RegistrationRequest registrationRequest) throws DataConversionException {
        return registrationManager.parse(registrationRequest);
    }

    public @NotNull RegistrationData parseRegistrationResponseJSON(
            @NotNull String registrationResponseJSON) throws DataConversionException {
        return registrationManager.parse(registrationResponseJSON);
    }

    public @NotNull AuthenticationData parse(
            @NotNull AuthenticationRequest authenticationRequest) throws DataConversionException {
        return authenticationManager.parse(authenticationRequest);
    }

    public @NotNull AuthenticationData parseAuthenticationResponseJSON(
            @NotNull String authenticationResponseJSON) throws DataConversionException {
        return authenticationManager.parse(authenticationResponseJSON);
    }

    public @NotNull RegistrationData verify(
            @NotNull RegistrationData registrationData,
            @NotNull SPCRegistrationParameters registrationParameters) throws VerificationException {
        registrationManager.verify(registrationData, registrationParameters);
        return registrationData;
    }

    public @NotNull AuthenticationData verify(
            @NotNull AuthenticationData authenticationData,
            @NotNull SPCAuthenticationParameters authenticationParameters) throws VerificationException {
        authenticationManager.verify(authenticationData, authenticationParameters);
        return authenticationData;
    }

    public @NotNull RegistrationData verify(
            @NotNull RegistrationRequest registrationRequest,
            @NotNull SPCRegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        RegistrationData registrationData = parse(registrationRequest);
        return verify(registrationData, registrationParameters);
    }

    public @NotNull RegistrationData verifyRegistrationResponseJSON(
            @NotNull String registrationResponseJSON,
            @NotNull SPCRegistrationParameters registrationParameters) throws DataConversionException, VerificationException {
        RegistrationData registrationData = parseRegistrationResponseJSON(registrationResponseJSON);
        return verify(registrationData, registrationParameters);
    }

    public @NotNull AuthenticationData verify(
            @NotNull AuthenticationRequest authenticationRequest,
            @NotNull SPCAuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        AuthenticationData authenticationData = parse(authenticationRequest);
        return verify(authenticationData, authenticationParameters);
    }

    public @NotNull AuthenticationData verifyAuthenticationResponseJSON(
            @NotNull String authenticationResponseJSON,
            @NotNull SPCAuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        AuthenticationData authenticationData = parseAuthenticationResponseJSON(authenticationResponseJSON);
        return verify(authenticationData, authenticationParameters);
    }
}
