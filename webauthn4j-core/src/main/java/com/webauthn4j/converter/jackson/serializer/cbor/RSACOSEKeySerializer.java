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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.attestation.authenticator.RSACOSEKey;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.jsontype.TypeSerializer;

import java.util.Arrays;

public class RSACOSEKeySerializer extends AbstractCtapCanonicalCborSerializer<RSACOSEKey> {

    public RSACOSEKeySerializer() {
        super(RSACOSEKey.class, Arrays.asList(
                new FieldSerializationRule<>(-8, RSACOSEKey::getQInv),
                new FieldSerializationRule<>(-7, RSACOSEKey::getDQ),
                new FieldSerializationRule<>(-6, RSACOSEKey::getDP),
                new FieldSerializationRule<>(-5, RSACOSEKey::getQ),
                new FieldSerializationRule<>(-4, RSACOSEKey::getP),
                new FieldSerializationRule<>(-3, RSACOSEKey::getD),
                new FieldSerializationRule<>(-2, RSACOSEKey::getE),
                new FieldSerializationRule<>(-1, RSACOSEKey::getN),
                new FieldSerializationRule<>(1, RSACOSEKey::getKeyType),
                new FieldSerializationRule<>(2, RSACOSEKey::getKeyId),
                new FieldSerializationRule<>(3, RSACOSEKey::getAlgorithm),
                new FieldSerializationRule<>(4, RSACOSEKey::getKeyOps),
                new FieldSerializationRule<>(5, RSACOSEKey::getBaseIV)
        ));
    }

    @Override
    public void serializeWithType(@NotNull RSACOSEKey value, @NotNull JsonGenerator gen,
                                  @NotNull SerializationContext provider, @NotNull TypeSerializer typeSer) {
        super.serialize(value, gen, provider);
    }
}
