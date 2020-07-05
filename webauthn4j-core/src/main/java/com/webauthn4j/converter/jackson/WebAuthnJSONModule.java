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

package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.webauthn4j.converter.jackson.deserializer.ChallengeDeserializer;
import com.webauthn4j.converter.jackson.deserializer.JWSDeserializer;
import com.webauthn4j.converter.jackson.deserializer.X509CertificateDeserializer;
import com.webauthn4j.converter.jackson.serializer.ChallengeSerializer;
import com.webauthn4j.converter.jackson.serializer.JWSSerializer;
import com.webauthn4j.converter.jackson.serializer.X509CertificateSerializer;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.jws.JWS;

import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn JSON data structures
 */
public class WebAuthnJSONModule extends SimpleModule {

    @SuppressWarnings("unused")
    public WebAuthnJSONModule(ObjectConverter objectConverter) {
        super("WebAuthnJSONModule");

        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(JWS.class, new JWSDeserializer(objectConverter));
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(new ChallengeSerializer());
        this.addSerializer(new JWSSerializer());
        this.addSerializer(new X509CertificateSerializer());

    }

}
