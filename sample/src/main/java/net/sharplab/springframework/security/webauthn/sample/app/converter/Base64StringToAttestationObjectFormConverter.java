package net.sharplab.springframework.security.webauthn.sample.app.converter;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToWebAuthnAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.sample.app.web.AttestationObjectForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class Base64StringToAttestationObjectFormConverter implements Converter<String, AttestationObjectForm> {

    @Autowired
    private Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter;

    public Base64StringToAttestationObjectFormConverter(Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter) {
        this.base64StringToWebAuthnAttestationObjectConverter = base64StringToWebAuthnAttestationObjectConverter;
    }

    @Override
    public AttestationObjectForm convert(String source) {
        WebAuthnAttestationObject attestationObject = base64StringToWebAuthnAttestationObjectConverter.convert(source);
        AttestationObjectForm attestationObjectForm = new AttestationObjectForm();
        attestationObjectForm.setAttestationObject(attestationObject);
        attestationObjectForm.setAttestationObjectBase64(source);
        return attestationObjectForm;
    }
}
