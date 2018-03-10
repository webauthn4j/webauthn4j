package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.sample.app.web.AttestationObjectForm;
import org.modelmapper.AbstractConverter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class AttestationObjectFormToWebAuthnAttestationObjectConverter extends AbstractConverter<AttestationObjectForm, WebAuthnAttestationObject> {

    @Override
    protected WebAuthnAttestationObject convert(AttestationObjectForm source) {
        return source.getAttestationObject();
    }
}
