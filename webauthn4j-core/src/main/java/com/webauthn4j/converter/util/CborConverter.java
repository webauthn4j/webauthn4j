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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A utility class for CBOR serialization/deserialization
 */
public class CborConverter {

    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";

    private final ObjectMapper cborMapper;

    CborConverter(@NonNull ObjectMapper cborMapper) {
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");
        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.cborMapper = cborMapper;
    }

    public @Nullable <T> T readValue(@NonNull byte[] src, @NonNull Class<T> valueType) {
        try {
            return cborMapper.readValue(src, valueType);
        } catch (MismatchedInputException | ValueInstantiationException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public @Nullable <T> T readValue(@NonNull InputStream src, @NonNull Class<T> valueType) {
        try {
            return cborMapper.readValue(src, valueType);
        } catch (MismatchedInputException | ValueInstantiationException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public @Nullable <T> T readValue(@NonNull byte[] src, @NonNull TypeReference<T> valueTypeRef) {
        try {
            return cborMapper.readValue(src, valueTypeRef);
        } catch (MismatchedInputException | ValueInstantiationException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public @Nullable <T> T readValue(@NonNull InputStream src, @NonNull TypeReference<T> valueTypeRef) {
        try {
            return cborMapper.readValue(src, valueTypeRef);
        } catch (MismatchedInputException | ValueInstantiationException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public @NonNull JsonNode readTree(@NonNull byte[] bytes) {
        try {
            return cborMapper.readTree(bytes);
        } catch (MismatchedInputException | ValueInstantiationException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public @NonNull byte[] writeValueAsBytes(@Nullable Object value) {
        try {
            return cborMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

}
