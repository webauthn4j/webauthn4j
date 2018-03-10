package net.sharplab.springframework.security.webauthn.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.util.jackson.WebAuthnModule;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Converter which converts from Base64{@link String} to {@link WebAuthnAttestationObject}
 */
public class Base64StringToWebAuthnAttestationObjectConverter implements Converter<String, WebAuthnAttestationObject> {

    private ObjectMapper objectMapper;

    public Base64StringToWebAuthnAttestationObjectConverter(){
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public WebAuthnAttestationObject convert(String source) {
        byte[] value = java.util.Base64.getUrlDecoder().decode(source);
        try {
            return objectMapper.readValue(value, WebAuthnAttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
