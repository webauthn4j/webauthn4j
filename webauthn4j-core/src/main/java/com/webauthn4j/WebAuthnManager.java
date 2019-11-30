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

import com.webauthn4j.converter.*;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.*;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.NullECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class WebAuthnManager {

    // ~ Instance fields
    // ================================================================================================

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final WebAuthnRegistrationDataValidator webAuthnRegistrationDataValidator;
    private final WebAuthnAuthenticationDataValidator webAuthnAuthenticationDataValidator;

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           List<CustomRegistrationValidator> customRegistrationValidators,
                           List<CustomAuthenticationValidator> customAuthenticationValidators,
                           JsonConverter jsonConverter,
                           CborConverter cborConverter) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(ecdaaTrustworthinessValidator, "ecdaaTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");
        AssertUtil.notNull(customRegistrationValidators, "customRegistrationValidators must not be null");
        AssertUtil.notNull(customAuthenticationValidators, "customAuthenticationValidators must not be null");
        AssertUtil.notNull(jsonConverter, "jsonConverter must not be null");
        AssertUtil.notNull(cborConverter, "cborConverter must not be null");

        webAuthnRegistrationDataValidator = new WebAuthnRegistrationDataValidator(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                jsonConverter,
                cborConverter);

        webAuthnAuthenticationDataValidator = new WebAuthnAuthenticationDataValidator(customAuthenticationValidators);

        collectedClientDataConverter = new CollectedClientDataConverter(jsonConverter);
        attestationObjectConverter = new AttestationObjectConverter(cborConverter);
        authenticatorDataConverter = new AuthenticatorDataConverter(cborConverter);
        authenticatorTransportConverter = new AuthenticatorTransportConverter();
        authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(jsonConverter);

    }

    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @return configured {@link WebAuthnManager}
     */
    public static WebAuthnManager createNonStrictWebAuthnManager() {
        return createNonStrictWebAuthnManager(new JsonConverter(), new CborConverter());
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @return configured {@link WebAuthnManager}
     */
    public static WebAuthnManager createNonStrictWebAuthnManager(JsonConverter jsonConverter, CborConverter cborConverter) {
        return new WebAuthnManager(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new NullFIDOU2FAttestationStatementValidator(),
                        new NullPackedAttestationStatementValidator(),
                        new NullTPMAttestationStatementValidator(),
                        new NullAndroidKeyAttestationStatementValidator(),
                        new NullAndroidSafetyNetAttestationStatementValidator()
                ),
                new NullCertPathTrustworthinessValidator(),
                new NullECDAATrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                Collections.emptyList(),
                Collections.emptyList(),
                jsonConverter,
                cborConverter
        );
    }


    public WebAuthnRegistrationData parseRegistrationRequest(WebAuthnRegistrationRequest webAuthnRegistrationRequest) throws DataConversionException {

        byte[] clientDataBytes = webAuthnRegistrationRequest.getClientDataJSON();
        byte[] attestationObjectBytes = webAuthnRegistrationRequest.getAttestationObject();

        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        Set<AuthenticatorTransport> transports = authenticatorTransportConverter.convertSet(webAuthnRegistrationRequest.getTransports());
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(webAuthnRegistrationRequest.getClientExtensionsJSON());

        return new WebAuthnRegistrationData(
                webAuthnRegistrationDataValidator,
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                transports
        );

    }

    public WebAuthnAuthenticationData parseAuthenticationRequest(WebAuthnAuthenticationRequest webAuthnAuthenticationRequest) throws DataConversionException{

        byte[] credentialId = webAuthnAuthenticationRequest.getCredentialId();
        byte[] signature = webAuthnAuthenticationRequest.getSignature();
        byte[] userHandle = webAuthnAuthenticationRequest.getUserHandle();
        byte[] clientDataBytes = webAuthnAuthenticationRequest.getClientDataJSON();
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        byte[] authenticatorDataBytes = webAuthnAuthenticationRequest.getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(webAuthnAuthenticationRequest.getClientExtensionsJSON());

        return new WebAuthnAuthenticationData(
                webAuthnAuthenticationDataValidator,
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

    public WebAuthnRegistrationDataValidator getWebAuthnRegistrationDataValidator() {
        return webAuthnRegistrationDataValidator;
    }

    public WebAuthnAuthenticationDataValidator getWebAuthnAuthenticationDataValidator() {
        return webAuthnAuthenticationDataValidator;
    }
}
