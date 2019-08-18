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
import com.webauthn4j.data.attestation.authenticator.EC2CredentialPublicKey;

import java.io.IOException;
import java.util.Arrays;

public class EC2CredentialPublicKeySerializer extends AbstractCtapCanonicalCborSerializer<EC2CredentialPublicKey> {

    public EC2CredentialPublicKeySerializer() {
        super(EC2CredentialPublicKey.class, Arrays.asList(
                new FieldSerializationRule<>(1, EC2CredentialPublicKey::getKeyType),
                new FieldSerializationRule<>(2, EC2CredentialPublicKey::getKeyId),
                new FieldSerializationRule<>(3, EC2CredentialPublicKey::getAlgorithm),
                new FieldSerializationRule<>(4, EC2CredentialPublicKey::getKeyOpts),
                new FieldSerializationRule<>(5, EC2CredentialPublicKey::getBaseIV),
                new FieldSerializationRule<>(-1, EC2CredentialPublicKey::getCurve),
                new FieldSerializationRule<>(-2, EC2CredentialPublicKey::getX),
                new FieldSerializationRule<>(-3, EC2CredentialPublicKey::getY)
        ));
    }

    @Override
    public void serializeWithType(EC2CredentialPublicKey value, JsonGenerator gen,
                                  SerializerProvider provider, TypeSerializer typeSer) throws IOException {
        super.serialize(value, gen, provider);
    }

}
