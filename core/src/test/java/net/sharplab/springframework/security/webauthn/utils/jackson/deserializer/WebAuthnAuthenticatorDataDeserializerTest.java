package net.sharplab.springframework.security.webauthn.utils.jackson.deserializer;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.util.jackson.deserializer.WebAuthnAuthenticatorDataDeserializer;
import org.junit.Test;
import org.springframework.util.Base64Utils;

import java.io.IOException;

import static net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for WebAuthnAuthenticatorDataDeserializer
 */
public class WebAuthnAuthenticatorDataDeserializerTest {

    @Test
    public void test() {
        //Given
        String input = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABRTBGAiEA77SC7T44f9E6NEEwiHBkcI3jSL70jAcvEN3lDJoFpxUCIQDxuc-Oq1UgYUxftfXu4wbsDQiTz_6cJJfe00d5t6nrNw==";

        //When
        WebAuthnAuthenticatorData result = new WebAuthnAuthenticatorDataDeserializer().deserialize(Base64Utils.decodeFromUrlSafeString(input));

        //Then
        assertThat(result.getRpIdHash()).isNotNull();
        assertThat(result.getRpIdHash()).hasSize(32);
        assertThat(result.getFlags()).isEqualTo(BIT_UP);
        assertThat(result.getCounter()).isEqualTo(325);
        assertThat(result.getAttestationData()).isNull();
        assertThat(result.getExtensions()).isNull();
    }
}
