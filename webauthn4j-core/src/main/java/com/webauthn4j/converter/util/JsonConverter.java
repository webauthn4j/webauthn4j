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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.util.AssertUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A utility class for JSON serialization/deserialization
 */
public class JsonConverter {

    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";

    /**
     * As it may not be initialized, jsonMapper must be used through getJsonMapper method
     */
    private ObjectMapper jsonMapper;
    private ObjectMapper cborMapper;

    private volatile boolean jsonMapperInitialized = false;
    private final Object jsonMapperInitializationLock = new Object();

    private CborConverter cborConverter;
    private volatile boolean cborConverterInitialized = false;
    private final Object cborConverterInitializationLock = new Object();

    public JsonConverter(ObjectMapper jsonMapper, ObjectMapper cborMapper) {
        AssertUtil.notNull(jsonMapper, "jsonMapper must not be null");
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");

        AssertUtil.isTrue(!(jsonMapper.getFactory() instanceof CBORFactory), "factory of jsonMapper must be JsonFactory.");
        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.jsonMapper = jsonMapper;
        this.cborMapper = cborMapper;
    }

    public JsonConverter() {
        this(new ObjectMapper(new JsonFactory()), new ObjectMapper(new CBORFactory()));
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(String src, Class valueType) {
        try {
            return (T) getJsonMapper().readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(InputStream src, Class valueType) {
        try {
            return (T) getJsonMapper().readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(String src, TypeReference valueTypeRef) {
        try {
            return getJsonMapper().readValue(src, valueTypeRef);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(InputStream src, TypeReference valueTypeRef) {
        try {
            return getJsonMapper().readValue(src, valueTypeRef);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value) {
        try {
            return getJsonMapper().writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String writeValueAsString(Object value) {
        try {
            return getJsonMapper().writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Returns the {@link ObjectMapper} configured for JSON processing
     *
     * @return the {@link ObjectMapper} configured for JSON processing
     */
    private ObjectMapper getJsonMapper() {
        if (!jsonMapperInitialized) {
            synchronized (jsonMapperInitializationLock){
                if (!jsonMapperInitialized) { // drop blocked calls
                    jsonMapper.registerModule(new WebAuthnJSONModule(this, getCborConverter()));
                    jsonMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
                    jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                    jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
                    jsonMapperInitialized = true;
                }
            }
        }
        return jsonMapper;
    }

    /**
     * Returns the twined {@link CborConverter}
     *
     * @return the twined {@link CborConverter}
     */
    public CborConverter getCborConverter() {
        if (!cborConverterInitialized) {
            synchronized (cborConverterInitializationLock){
                if(!cborConverterInitialized){ // drop blocked calls
                    cborConverter = new CborConverter(jsonMapper, cborMapper);
                    cborConverterInitialized = true;
                }
            }
        }
        return cborConverter;
    }
}
