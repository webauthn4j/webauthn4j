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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.data.attestation.authenticator.COSEKey;

import java.io.IOException;

/**
 * Jackson Deserializer for {@link COSEKeyEnvelope}
 */
public class COSEKeyEnvelopeDeserializer extends StdDeserializer<COSEKeyEnvelope> {

    public COSEKeyEnvelopeDeserializer() {
        super(COSEKeyEnvelope.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public COSEKeyEnvelope deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        COSEKey coseKey = ctxt.readValue(p, COSEKey.class);
        int length = (int) p.getCurrentLocation().getByteOffset();
        return new COSEKeyEnvelope(coseKey, length);
    }
}