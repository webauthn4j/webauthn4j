package com.webauthn4j.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.ExtensionIdentifier;
import com.webauthn4j.extension.client.ClientExtensionOutput;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;

public class ClientExtensionOutputsConverter {

    private final ObjectMapper cborMapper = ObjectMapperUtil.createCBORMapper();

    public Map<ExtensionIdentifier, ClientExtensionOutput> convert(byte[] value){
        try {
            if(value == null){
                return null;
            }
            return cborMapper.readValue(value, new TypeReference<Map<ExtensionIdentifier, ClientExtensionOutput>>(){});
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
