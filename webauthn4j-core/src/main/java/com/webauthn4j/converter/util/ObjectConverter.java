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
 * A set of object converter classes
 */
public class ObjectConverter {

    private final JsonConverter jsonConverter;
    private final CborConverter cborConverter;

    public ObjectConverter(@NotNull JsonMapper jsonMapper, @NotNull CBORMapper cborMapper) {
        AssertUtil.notNull(jsonMapper, "jsonMapper must not be null");
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");

        JsonMapper initializedJsonMapper = initializeJsonMapper(jsonMapper, this);
        CBORMapper initializedCborMapper = initializeCborMapper(cborMapper, this);

        this.jsonConverter = new JsonConverter(initializedJsonMapper);
        this.cborConverter = new CborConverter(initializedCborMapper);
    }

    public ObjectConverter() {
        this(new JsonMapper(), new CBORMapper());
    }

    /**
     * Initialize a {@link ObjectMapper} for WebAuthn JSON type processing
     */
    private static JsonMapper initializeJsonMapper(@NotNull JsonMapper jsonMapper, @NotNull ObjectConverter objectConverter) {
        return jsonMapper.rebuild()
                .addModule(new WebAuthnJSONModule(objectConverter))
                .configure(DeserializationFeature.WRAP_EXCEPTIONS, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false) //TODO: revert to Jackson2 behavior, but this need to be removed before release
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, true) //TODO: revert to Jackson2 behavior, but this need to be removed before release
                .changeDefaultPropertyInclusion(incl -> incl
                        .withValueInclusion(JsonInclude.Include.NON_NULL)
                        .withContentInclusion(JsonInclude.Include.NON_NULL))
                .build();
    }

    /**y
     * Initialize a {@link ObjectMapper} for WebAuthn CBOR type processing
     */
    private static CBORMapper initializeCborMapper(@NotNull CBORMapper cborMapper, @NotNull ObjectConverter objectConverter) {
        return cborMapper.rebuild()
                .addModule(new WebAuthnCBORModule(objectConverter))
                .configure(DeserializationFeature.WRAP_EXCEPTIONS, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false) //TODO: revert to Jackson2 behavior, but this need to be removed before release
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, true) //TODO: revert to Jackson2 behavior, but this need to be removed before release
                .changeDefaultPropertyInclusion(incl -> incl
                        .withValueInclusion(JsonInclude.Include.NON_NULL)
                        .withContentInclusion(JsonInclude.Include.NON_NULL))
                .build();
    }

    //TODO: deprecate
    public @NotNull JsonConverter getJsonConverter() {
        return jsonConverter;
    }

    //TODO: deprecate
    public @NotNull CborConverter getCborConverter() {
        return cborConverter;
    }

}
