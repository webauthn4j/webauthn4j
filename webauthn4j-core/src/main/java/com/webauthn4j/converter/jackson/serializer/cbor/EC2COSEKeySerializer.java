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

import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.jsontype.TypeSerializer;

import java.util.Arrays;

public class EC2COSEKeySerializer extends AbstractCtapCanonicalCborSerializer<EC2COSEKey> {

    public EC2COSEKeySerializer() {
        super(EC2COSEKey.class, Arrays.asList(
                new FieldSerializationRule<>(1, EC2COSEKey::getKeyType),
                new FieldSerializationRule<>(2, EC2COSEKey::getKeyId),
                new FieldSerializationRule<>(3, EC2COSEKey::getAlgorithm),
                new FieldSerializationRule<>(4, EC2COSEKey::getKeyOps),
                new FieldSerializationRule<>(5, EC2COSEKey::getBaseIV),
                new FieldSerializationRule<>(-1, EC2COSEKey::getCurve),
                new FieldSerializationRule<>(-2, EC2COSEKey::getX),
                new FieldSerializationRule<>(-3, EC2COSEKey::getY),
                new FieldSerializationRule<>(-4, EC2COSEKey::getD)
        ));
    }

    @Override
    public void serializeWithType(@NotNull EC2COSEKey value, @NotNull JsonGenerator gen,
                                  @NotNull SerializationContext provider, @NotNull TypeSerializer typeSer) {
        super.serialize(value, gen, provider);
    }

}
