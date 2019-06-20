package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

public abstract class AbstractCborConverter {
    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";
    
     ObjectMapper cborMapper;

    @SuppressWarnings("unchecked")
    public <T> T readValue(byte[] src, Class valueType) {
        try {
            return (T) cborMapper.readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T> T readValue(InputStream src, Class valueType) {
        try {
            return (T) cborMapper.readValue(src, valueType);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T readValue(byte[] src, TypeReference valueTypeRef) {
        try {
            return cborMapper.readValue(src, valueTypeRef);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public AuthenticationExtensionsAuthenticatorOutputs readValue(InputStream inputStream, TypeReference<AuthenticationExtensionsAuthenticatorOutputs> typeReference) {
        try {
            return cborMapper.readValue(inputStream, typeReference);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public JsonNode readTree(byte[] bytes) {
        try {
            return cborMapper.readTree(bytes);
        } catch (MismatchedInputException | JsonParseException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] writeValueAsBytes(Object value) {
        try {
            return cborMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

}
