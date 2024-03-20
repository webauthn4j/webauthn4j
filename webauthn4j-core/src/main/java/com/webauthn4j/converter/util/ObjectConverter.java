/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

/**
 * A set of object converter classes
 */
public class ObjectConverter {

    private final JsonConverter jsonConverter;
    private final CborConverter cborConverter;

    public ObjectConverter(@NonNull ObjectMapper jsonMapper, @NonNull ObjectMapper cborMapper) {
        AssertUtil.notNull(jsonMapper, "jsonMapper must not be null");
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");
        AssertUtil.isTrue(!(jsonMapper.getFactory() instanceof CBORFactory), "factory of jsonMapper must be JsonFactory.");
        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.jsonConverter = new JsonConverter(jsonMapper);
        this.cborConverter = new CborConverter(cborMapper);

        initializeJsonMapper(jsonMapper, this);
        initializeCborMapper(cborMapper, this);
    }

    public ObjectConverter() {
        this(new ObjectMapper(), new ObjectMapper(new CBORFactory()));
    }

    /**
     * Initialize a {@link ObjectMapper} for WebAuthn JSON type processing
     */
    private static void initializeJsonMapper(@NonNull ObjectMapper jsonMapper, @NonNull ObjectConverter objectConverter) {
        jsonMapper.registerModule(new WebAuthnJSONModule(objectConverter));
        jsonMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * Initialize a {@link ObjectMapper} for WebAuthn CBOR type processing
     */
    private static void initializeCborMapper(@NonNull ObjectMapper cborMapper, @NonNull ObjectConverter objectConverter) {
        cborMapper.registerModule(new WebAuthnCBORModule(objectConverter));
        cborMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
        cborMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        cborMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public @NonNull JsonConverter getJsonConverter() {
        return jsonConverter;
    }

    public @NonNull CborConverter getCborConverter() {
        return cborConverter;
    }

}
