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
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.response.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
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
    private ObjectMapper cborMapper;

    private boolean jsonMapperInitialized = false;
    private boolean cborMapperInitialized = false;

    private JsonConverter jsonConverter;

    public CborConverter(ObjectMapper jsonMapper, ObjectMapper cborMapper) {
        AssertUtil.isTrue(!(jsonMapper.getFactory() instanceof CBORFactory), "factory of jsonMapper must be JsonFactory.");
        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.jsonMapper = jsonMapper;
        this.cborMapper = cborMapper;
    }

    public CborConverter(){
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

    public ObjectMapper getJsonMapper() {
        if(!jsonMapperInitialized){
            jsonMapper.registerModule(new WebAuthnJSONModule(getJsonConverter(), this));
            jsonMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
            jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            jsonMapperInitialized = true;
        }
        return jsonMapper;
    }

    public ObjectMapper getCborMapper() {
        if(!cborMapperInitialized){
            cborMapper.registerModule(new WebAuthnCBORModule(getJsonConverter(), this));
            cborMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
            cborMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            cborMapperInitialized = true;
        }
        return cborMapper;
    }

    public JsonConverter getJsonConverter() {
        if (jsonConverter == null) {
            jsonConverter = new JsonConverter(jsonMapper, cborMapper);
        }
        return jsonConverter;
    }
}
