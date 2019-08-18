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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.webauthn4j.data.attestation.authenticator.RSACredentialPublicKey;

import java.io.IOException;
import java.util.Arrays;

public class RSACredentialPublicKeySerializer extends AbstractCtapCanonicalCborSerializer<RSACredentialPublicKey> {

    public RSACredentialPublicKeySerializer() {
        super(RSACredentialPublicKey.class, Arrays.asList(
                new FieldSerializationRule<>(1, RSACredentialPublicKey::getKeyType),
                new FieldSerializationRule<>(2, RSACredentialPublicKey::getKeyId),
                new FieldSerializationRule<>(3, RSACredentialPublicKey::getAlgorithm),
                new FieldSerializationRule<>(4, RSACredentialPublicKey::getKeyOpts),
                new FieldSerializationRule<>(5, RSACredentialPublicKey::getBaseIV),
                new FieldSerializationRule<>(-1, RSACredentialPublicKey::getN),
                new FieldSerializationRule<>(-2, RSACredentialPublicKey::getE)
        ));
    }

    @Override
    public void serializeWithType(RSACredentialPublicKey value, JsonGenerator gen,
                                  SerializerProvider provider, TypeSerializer typeSer) throws IOException {
        super.serialize(value, gen, provider);
    }
}
