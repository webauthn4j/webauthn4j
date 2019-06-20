package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.util.AssertUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

public abstract class AbstractJsonConverter {
    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";
    private ObjectMapper jsonMapper;

    AbstractJsonConverter(ObjectMapper mapper, SimpleModule module) {
        this(mapper, module, false, false);
    }

    AbstractJsonConverter(ObjectMapper mapper,
                          SimpleModule module,
                          Boolean wrapExceptions,
                          Boolean failOnUnknownProperties) {
        AssertUtil.notNull(mapper, "jsonMapper must not be null");

        AssertUtil.isTrue(!(mapper.getFactory() instanceof CBORFactory), "factory of jsonMapper must be JsonFactory.");

        this.jsonMapper = mapper;

        this.jsonMapper.registerModule(module);
        this.jsonMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, wrapExceptions);
        this.jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, failOnUnknownProperties);
        this.jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(String src, Class valueType) {
        try {
            return (T) jsonMapper.readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(InputStream src, Class valueType) {
        try {
            return (T) jsonMapper.readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(String src, TypeReference valueTypeRef) {
        try {
            return jsonMapper.readValue(src, valueTypeRef);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(InputStream src, TypeReference valueTypeRef) {
        try {
            return jsonMapper.readValue(src, valueTypeRef);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value) {
        try {
            return jsonMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String writeValueAsString(Object value) {
        try {
            return jsonMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }
}
