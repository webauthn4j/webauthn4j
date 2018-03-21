package net.sharplab.springframework.security.webauthn.sample.app.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import net.sharplab.springframework.security.webauthn.sample.app.web.AttestationObjectForm;
import com.webauthn4j.webauthn.util.WebAuthnModule;
import org.springframework.core.convert.converter.Converter;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Converter which converts from {@link AttestationObjectForm} to {@link String}
 */
public class AttestationObjectFormToBase64StringConverter implements Converter<AttestationObjectForm, String> {

    private ObjectMapper objectMapper;

    public AttestationObjectFormToBase64StringConverter() {
        this.objectMapper = new ObjectMapper(new CBORFactory());
        this.objectMapper.registerModule(new WebAuthnModule());
    }

    @Override
    public String convert(AttestationObjectForm source) {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(source);
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
