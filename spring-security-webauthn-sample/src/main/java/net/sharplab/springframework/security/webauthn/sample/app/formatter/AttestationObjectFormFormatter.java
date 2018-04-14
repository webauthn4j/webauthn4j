package net.sharplab.springframework.security.webauthn.sample.app.formatter;

import com.webauthn4j.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToWebAuthnAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.sample.app.web.AttestationObjectForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.Formatter;

import java.text.ParseException;
import java.util.Locale;

/**
 * Converter which converts from {@link AttestationObjectForm} to {@link String}
 */
public class AttestationObjectFormFormatter implements Formatter<AttestationObjectForm> {

    @Autowired
    private Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter;

    public AttestationObjectFormFormatter(Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter) {
        this.base64StringToWebAuthnAttestationObjectConverter = base64StringToWebAuthnAttestationObjectConverter;
    }

    @Override
    public AttestationObjectForm parse(String text, Locale locale) throws ParseException {
        WebAuthnAttestationObject attestationObject = base64StringToWebAuthnAttestationObjectConverter.convert(text);
        AttestationObjectForm attestationObjectForm = new AttestationObjectForm();
        attestationObjectForm.setAttestationObject(attestationObject);
        attestationObjectForm.setAttestationObjectBase64(text);
        return attestationObjectForm;
    }

    @Override
    public String print(AttestationObjectForm object, Locale locale) {
        return object.getAttestationObjectBase64();
    }
}
