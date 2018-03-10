package net.sharplab.springframework.security.webauthn.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.util.jackson.WebAuthnModule;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Converter which converts from Base64{@link String} to {@link ClientData}
 */
public class Base64StringToClientDataConverter implements Converter<String, ClientData> {

    private ObjectMapper objectMapper;

    public Base64StringToClientDataConverter(){
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public ClientData convert(String source) {
        byte[] jsonBytes = java.util.Base64.getUrlDecoder().decode(source);
        String jsonString = new String(jsonBytes, StandardCharsets.UTF_8);
        try {
            return objectMapper.readValue(jsonString, ClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
