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

package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.attestation.WebAuthnAttestationObject;
import com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.jackson.deserializer.*;
import com.webauthn4j.jackson.serializer.*;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

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
        this.addDeserializer(WebAuthnAttestationObject.class, new WebAuthnAttestationObjectDeserializer());
        this.addDeserializer(WebAuthnAuthenticatorData.class, new WebAuthnAuthenticatorDataDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(CertPath.class, new CertPathSerializer());
        this.addSerializer(Challenge.class, new ChallengeSerializer());
        this.addSerializer(Origin.class, new OriginSerializer());
        this.addSerializer(WebAuthnAuthenticatorData.class, new WebAuthnAuthenticatorDataSerializer());
        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        //metadata
        this.addDeserializer(LocalDate.class, new LocalDateDeserializer());
    }

}
