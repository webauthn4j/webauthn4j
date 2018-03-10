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
 * Converter which converts from {@link WebAuthnAttestationObject} to {@link String}
 */
public class WebAuthnAttestationObjectToBase64StringConverter implements Converter<WebAuthnAttestationObject, String> {

    private ObjectMapper objectMapper;

    public WebAuthnAttestationObjectToBase64StringConverter(){
        this.objectMapper = new ObjectMapper(new CBORFactory());
        this.objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public String convert(WebAuthnAttestationObject source) {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(source);
            return Base64Utils.encodeToUrlSafeString(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
