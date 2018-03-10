package net.sharplab.springframework.security.webauthn.converter;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAttestationObjectToBase64StringConverterTest {

    private WebAuthnAttestationObjectToBase64StringConverter target = new WebAuthnAttestationObjectToBase64StringConverter();
    private Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter = new Base64StringToWebAuthnAttestationObjectConverter();

    @Test
    public void convert_test(){
        WebAuthnAttestationObject input = CoreTestUtil.createWebAuthnAttestationObjectWithFIDOU2FAttestationStatement();
        String result = target.convert(input);
        WebAuthnAttestationObject deserialized = base64StringToWebAuthnAttestationObjectConverter.convert(result);
        assertThat(deserialized).isEqualTo(input);
    }
}
