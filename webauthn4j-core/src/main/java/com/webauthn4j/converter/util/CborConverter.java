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
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.util.AssertUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A utility class for CBOR serialization/deserialization
 */
public class CborConverter {

    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";

    private ObjectMapper jsonMapper;

    /**
     * As it may not be initialized, cborMapper must be used through getCborMapper method
     */
    private ObjectMapper cborMapper;

    private volatile boolean cborMapperInitialized = false;
    private final Object cborMapperInitializationLock = new Object();

    private JsonConverter jsonConverter;
    private volatile boolean jsonConverterInitialized = false;
    private final Object jsonConverterInitializationLock = new Object();

    public CborConverter(ObjectMapper jsonMapper, ObjectMapper cborMapper) {
        AssertUtil.notNull(jsonMapper, "jsonMapper must not be null");
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");

        AssertUtil.isTrue(!(jsonMapper.getFactory() instanceof CBORFactory), "factory of jsonMapper must be JsonFactory.");
        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.jsonMapper = jsonMapper;
        this.cborMapper = cborMapper;
    }

    public CborConverter() {
        this(new ObjectMapper(), new ObjectMapper(new CBORFactory()));
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(byte[] src, Class valueType) {
        try {
            return (T) getCborMapper().readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(InputStream src, Class valueType) {
        try {
            return (T) getCborMapper().readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(byte[] src, TypeReference valueTypeRef) {
        try {
            return getCborMapper().readValue(src, valueTypeRef);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public AuthenticationExtensionsAuthenticatorOutputs readValue(InputStream inputStream, TypeReference<AuthenticationExtensionsAuthenticatorOutputs> typeReference) {
        try {
            return getCborMapper().readValue(inputStream, typeReference);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public JsonNode readTree(byte[] bytes) {
        try {
            return getCborMapper().readTree(bytes);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value) {
        try {
            return getCborMapper().writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Returns the {@link ObjectMapper} configured for CBOR processing
     *
     * @return the {@link ObjectMapper} configured for CBOR processing
     */
    private ObjectMapper getCborMapper() {
        if (!cborMapperInitialized) {
            synchronized (cborMapperInitializationLock){
                if(!cborMapperInitialized){ // drop blocked calls
                    cborMapper.registerModule(new WebAuthnCBORModule(getJsonConverter(), this));
                    cborMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
                    cborMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                    cborMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
                    cborMapperInitialized = true;
                }
            }
        }
        return cborMapper;
    }

    /**
     * Returns the twined {@link JsonConverter}
     *
     * @return the twined {@link JsonConverter}
     */
    public JsonConverter getJsonConverter() {
        if (!jsonConverterInitialized) {
            synchronized (jsonConverterInitializationLock){
                if(!jsonConverterInitialized){ // drop blocked calls
                    jsonConverter = new JsonConverter(jsonMapper, cborMapper);
                    jsonConverterInitialized = true;
                }
            }
        }
        return jsonConverter;
    }
}
