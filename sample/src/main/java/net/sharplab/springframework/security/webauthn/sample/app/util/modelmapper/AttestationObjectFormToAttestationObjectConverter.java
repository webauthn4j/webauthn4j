package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper;

import com.webauthn4j.attestation.AttestationObject;
import net.sharplab.springframework.security.webauthn.sample.app.web.AttestationObjectForm;
import org.modelmapper.AbstractConverter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class AttestationObjectFormToAttestationObjectConverter extends AbstractConverter<AttestationObjectForm, AttestationObject> {

    @Override
    protected AttestationObject convert(AttestationObjectForm source) {
        return source.getAttestationObject();
    }
}
