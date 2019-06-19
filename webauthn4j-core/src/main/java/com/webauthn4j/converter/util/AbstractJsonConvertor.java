package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.webauthn4j.converter.exception.DataConversionException;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

public class AbstractJsonConvertor {
    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";
    ObjectMapper jsonMapper;

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
        return jsonMapper;
    }
}
