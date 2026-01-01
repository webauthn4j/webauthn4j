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
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

/**
 * A set of JSON mapper and CBOR mapper classes specialized for WebAuthn serialization/deserialization
 */
public class ObjectConverter {

    JsonMapper jsonMapper;
    CBORMapper cborMapper;
    private final JsonConverter jsonConverter;
    private final CborConverter cborConverter;

    public ObjectConverter(@NotNull JsonMapper jsonMapper, @NotNull CBORMapper cborMapper) {
        AssertUtil.notNull(jsonMapper, "jsonMapper must not be null");
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");

        this.jsonMapper = reconfigureJsonMapper(jsonMapper, this);
        this.cborMapper = reconfigureCborMapper(cborMapper, this);

        this.jsonConverter = new JsonConverter(this);
        this.cborConverter = new CborConverter(this);
    }

    public ObjectConverter() {
        this(new JsonMapper(), new CBORMapper());
    }

    /**
     * Reconfigure a {@link ObjectMapper} for WebAuthn JSON type processing
     */
    private static JsonMapper reconfigureJsonMapper(@NotNull JsonMapper jsonMapper, @NotNull ObjectConverter objectConverter) {
        return jsonMapper.rebuild()
                .addModule(new WebAuthnJSONModule(objectConverter))
                .configure(DeserializationFeature.WRAP_EXCEPTIONS, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .changeDefaultPropertyInclusion(incl -> incl
                        .withValueInclusion(JsonInclude.Include.NON_NULL)
                        .withContentInclusion(JsonInclude.Include.NON_NULL))
                .build();
    }

    /**
     * Reconfigure a {@link ObjectMapper} for WebAuthn CBOR type processing
     */
    private static CBORMapper reconfigureCborMapper(@NotNull CBORMapper cborMapper, @NotNull ObjectConverter objectConverter) {
        return cborMapper.rebuild()
                .addModule(new WebAuthnCBORModule(objectConverter))
                .configure(DeserializationFeature.WRAP_EXCEPTIONS, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .changeDefaultPropertyInclusion(incl -> incl
                        .withValueInclusion(JsonInclude.Include.NON_NULL)
                        .withContentInclusion(JsonInclude.Include.NON_NULL))
                .build();
    }

    /**
     * @deprecated Use {@link #getJsonMapper()} instead.
     * The {@link JsonConverter} was a thin wrapper around {@link ObjectMapper} and wrapped checked exceptions into unchecked ones.
     * It also specified at the type level whether it was a JSON or CBOR converter.
     * However, since Jackson 3 introduced {@link JsonMapper} specifically for JSON and it no longer throws checked exceptions, {@link JsonConverter} has been deprecated.
     */
    @Deprecated
    public @NotNull JsonConverter getJsonConverter() {
        return jsonConverter;
    }

    /**
     * @deprecated Use {@link #getCborMapper()} instead.
     * The {@link CborConverter} was a thin wrapper around {@link ObjectMapper} and wrapped checked exceptions into unchecked ones.
     * It also specified at the type level whether it was a JSON or CBOR converter.
     * However, since Jackson 3 introduced {@link CBORMapper} specifically for CBOR and it no longer throws checked exceptions, {@link CborConverter} has been deprecated.
     */
    @Deprecated
    public @NotNull CborConverter getCborConverter() {
        return cborConverter;
    }

    public @NotNull JsonMapper getJsonMapper() {
        return jsonMapper;
    }

    public @NotNull CBORMapper getCborMapper() {
        return cborMapper;
    }

}
