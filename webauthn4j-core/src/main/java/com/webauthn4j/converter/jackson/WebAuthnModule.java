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

package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.*;
import com.webauthn4j.converter.jackson.serializer.*;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.request.extension.client.ExtensionClientInput;
import com.webauthn4j.request.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.request.extension.client.SupportedExtensionsExtensionClientInput;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.extension.authenticator.*;
import com.webauthn4j.response.extension.client.*;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn classes serialization and deserialization
 */
public class WebAuthnModule extends SimpleModule {

    public WebAuthnModule(Registry registry) {
        super("WebAuthnModule");

        this.addDeserializer(AuthenticationExtensionsAuthenticatorOutputsEnvelope.class, new AuthenticationExtensionsAuthenticatorOutputsEnvelopeDeserializer());
        this.addDeserializer(CertPath.class, new CertPathDeserializer());
        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(CredentialPublicKeyEnvelope.class, new CredentialPublicKeyEnvelopeDeserializer());
        this.addDeserializer(AuthenticatorData.class, new AuthenticatorDataDeserializer(registry));
        this.addDeserializer(ExtensionAuthenticatorOutput.class, new ExtensionAuthenticatorOutputDeserializer());
        this.addDeserializer(ExtensionClientInput.class, new ExtensionClientInputDeserializer());
        this.addDeserializer(ExtensionClientOutput.class, new ExtensionClientOutputDeserializer());
        this.addDeserializer(JWS.class, new JWSDeserializer(registry));
        this.addDeserializer(TPMSAttest.class, new TPMSAttestDeserializer());
        this.addDeserializer(TPMTPublic.class, new TPMTPublicDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(CertPath.class, new CertPathSerializer());
        this.addSerializer(Challenge.class, new ChallengeSerializer());
        this.addSerializer(Origin.class, new OriginSerializer());
        this.addSerializer(AuthenticatorData.class, new AuthenticatorDataSerializer(registry));
        this.addSerializer(JWS.class, new JWSSerializer());
        this.addSerializer(TPMSAttest.class, new TPMSAttestSerializer());
        this.addSerializer(TPMTPublic.class, new TPMTPublicSerializer());
        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        this.registerSubtypes(new NamedType(FIDOU2FAttestationStatement.class, FIDOU2FAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(PackedAttestationStatement.class, PackedAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidKeyAttestationStatement.class, AndroidKeyAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(AndroidSafetyNetAttestationStatement.class, AndroidSafetyNetAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(TPMAttestationStatement.class, TPMAttestationStatement.FORMAT));
        this.registerSubtypes(new NamedType(NoneAttestationStatement.class, NoneAttestationStatement.FORMAT));

        this.registerSubtypes(new NamedType(FIDOAppIDExtensionClientInput.class, FIDOAppIDExtensionClientInput.ID));
        this.registerSubtypes(new NamedType(SupportedExtensionsExtensionClientInput.class, SupportedExtensionsExtensionClientInput.ID));

        this.registerSubtypes(new NamedType(AuthenticatorSelectionExtensionClientOutput.class, AuthenticatorSelectionExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(BiometricAuthenticatorPerformanceBoundsExtensionClientOutput.class, BiometricAuthenticatorPerformanceBoundsExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(FIDOAppIDExtensionClientOutput.class, FIDOAppIDExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(GenericTransactionAuthorizationExtensionClientOutput.class, GenericTransactionAuthorizationExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(LocationExtensionClientOutput.class, LocationExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(SimpleTransactionAuthorizationExtensionClientOutput.class, SimpleTransactionAuthorizationExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(SupportedExtensionsExtensionClientOutput.class, SupportedExtensionsExtensionClientOutput.ID));
        this.registerSubtypes(new NamedType(UserVerificationIndexExtensionClientOutput.class, UserVerificationIndexExtensionClientOutput.ID));

        this.registerSubtypes(new NamedType(GenericTransactionAuthorizationExtensionAuthenticatorOutput.class, GenericTransactionAuthorizationExtensionAuthenticatorOutput.ID));
        this.registerSubtypes(new NamedType(LocationExtensionAuthenticatorOutput.class, LocationExtensionAuthenticatorOutput.ID));
        this.registerSubtypes(new NamedType(SimpleTransactionAuthorizationExtensionAuthenticatorOutput.class, SimpleTransactionAuthorizationExtensionAuthenticatorOutput.ID));
        this.registerSubtypes(new NamedType(SupportedExtensionsExtensionAuthenticatorOutput.class, SupportedExtensionsExtensionAuthenticatorOutput.ID));
        this.registerSubtypes(new NamedType(UserVerificationIndexExtensionAuthenticatorOutput.class, UserVerificationIndexExtensionAuthenticatorOutput.ID));

    }

}
