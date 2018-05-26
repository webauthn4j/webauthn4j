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
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.converter.jackson.deserializer.*;
import com.webauthn4j.converter.jackson.serializer.*;
import com.webauthn4j.extension.ExtensionOutput;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn classes serialization and deserialization
 */
public class WebAuthnModule extends SimpleModule {

    /**
     * Default constructor
     */
    public WebAuthnModule() {
        super("WebAuthnModule");

        this.addDeserializer(CertPath.class, new CertPathDeserializer());
        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(AuthenticatorData.class, new AuthenticatorDataDeserializer());
        this.addDeserializer(ExtensionOutput.class, new ExtensionOutputDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(CertPath.class, new CertPathSerializer());
        this.addSerializer(Challenge.class, new ChallengeSerializer());
        this.addSerializer(Origin.class, new OriginSerializer());
        this.addSerializer(AuthenticatorData.class, new AuthenticatorDataSerializer());
        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        this.registerSubtypes(FIDOU2FAttestationStatement.class);
        this.registerSubtypes(PackedAttestationStatement.class);
        this.registerSubtypes(NoneAttestationStatement.class);

    }

}
