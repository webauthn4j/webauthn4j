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

package com.webauthn4j.converter.util;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.exc.InvalidDefinitionException;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.exc.ValueInstantiationException;

import java.io.InputStream;

/**
 * A utility class for CBOR serialization/deserialization
 */
@Deprecated
public class CborConverter {

    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";

    private final ObjectConverter objectConverter;

    CborConverter(@NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.objectConverter = objectConverter;
    }

    @Deprecated
    public void registerModule(JacksonModule module){
        this.objectConverter.cborMapper = objectConverter.getCborMapper().rebuild()
                .addModule(module)
                .build();
    }

    public @Nullable <T> T readValue(@NotNull byte[] src, @NotNull Class<T> valueType) {
        try {
            return this.objectConverter.getCborMapper().readValue(src, valueType);
        } catch (MismatchedInputException | ValueInstantiationException | StreamReadException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
    }

    public @Nullable <T> T readValue(@NotNull InputStream src, @NotNull Class<T> valueType) {
        try {
            return this.objectConverter.getCborMapper().readValue(src, valueType);
        } catch (MismatchedInputException | ValueInstantiationException | StreamReadException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
    }

    public @Nullable <T> T readValue(@NotNull byte[] src, @NotNull TypeReference<T> valueTypeRef) {
        try {
            return this.objectConverter.getCborMapper().readValue(src, valueTypeRef);
        } catch (MismatchedInputException | ValueInstantiationException | StreamReadException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
    }

    public @Nullable <T> T readValue(@NotNull InputStream src, @NotNull TypeReference<T> valueTypeRef) {
        try {
            return this.objectConverter.getCborMapper().readValue(src, valueTypeRef);
        } catch (MismatchedInputException | ValueInstantiationException | StreamReadException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
    }

    public @NotNull JsonNode readTree(@NotNull byte[] bytes) {
        try {
            return this.objectConverter.getCborMapper().readTree(bytes);
        } catch (MismatchedInputException | ValueInstantiationException | StreamReadException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
    }

    public @NotNull byte[] writeValueAsBytes(@Nullable Object value) {
        try {
            return this.objectConverter.getCborMapper().writeValueAsBytes(value);
        } catch (InvalidDefinitionException e) {
            throw new DataConversionException(e);
        }
    }

}
