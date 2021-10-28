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
import com.webauthn4j.converter.jackson.deserializer.json.ChallengeDeserializer;
import com.webauthn4j.converter.jackson.deserializer.json.CredentialProtectionPolicyDeserializer;
import com.webauthn4j.converter.jackson.deserializer.json.JWSHeaderDeserializer;
import com.webauthn4j.converter.jackson.deserializer.json.X509CertificateDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.*;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.cert.X509Certificate;

/**
 * Jackson Module for WebAuthn JSON data structures
 */
public class WebAuthnJSONModule extends SimpleModule {

    @SuppressWarnings("unused")
    public WebAuthnJSONModule(@NonNull ObjectConverter objectConverter) {
        super("WebAuthnJSONModule");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(CredentialProtectionPolicy.class, new CredentialProtectionPolicyDeserializer());
        this.addDeserializer(JWSHeader.class, new JWSHeaderDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(new ChallengeSerializer());
        this.addSerializer(new CredentialProtectionPolicySerializer());
        this.addSerializer(new JWSHeaderSerializer());
        this.addSerializer(new OriginSerializer());
        this.addSerializer(new X509CertificateSerializer());

    }

}
