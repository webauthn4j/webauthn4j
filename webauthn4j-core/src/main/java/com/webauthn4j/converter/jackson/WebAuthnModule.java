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

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.*;
import com.webauthn4j.converter.jackson.serializer.*;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.response.attestation.statement.JWS;
import com.webauthn4j.response.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.response.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.response.extension.client.ExtensionClientOutput;

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
        this.addDeserializer(ExtensionAuthenticatorOutput.class, new AuthenticatorExtensionOutputDeserializer());
        this.addDeserializer(ExtensionClientOutput.class, new ExtensionClientOutputDeserializer());
        this.addDeserializer(JWS.class, new JWSDeserializer(registry));
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(CertPath.class, new CertPathSerializer());
        this.addSerializer(Challenge.class, new ChallengeSerializer());
        this.addSerializer(Origin.class, new OriginSerializer());
        this.addSerializer(AuthenticatorData.class, new AuthenticatorDataSerializer(registry));
        this.addSerializer(JWS.class, new JWSSerializer());
        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        this.registerSubtypes(FIDOU2FAttestationStatement.class);
        this.registerSubtypes(PackedAttestationStatement.class);
        this.registerSubtypes(NoneAttestationStatement.class);

    }

}
