package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.webauthn4j.attestation.authenticator.Curve;
import com.webauthn4j.attestation.authenticator.ESSignatureAlgorithm;
import com.webauthn4j.attestation.authenticator.RSSignatureAlgorithm;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AbstractCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ESCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.RSCredentialPublicKeyVO;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class CredentialPublicKeyVOConverterTest {

    private CredentialPublicKeyVOConverter target = new CredentialPublicKeyVOConverter();

    @Test
    public void testESCredentialPublicKeyVO(){
        ESCredentialPublicKeyVO original= new ESCredentialPublicKeyVO();
        original.setCurve(Curve.SECP256R1);
        original.setAlgorithm(ESSignatureAlgorithm.SHA256withECDSA);
        original.setX(new byte[]{0b00, 0b01});
        original.setY(new byte[]{0b10, 0b11});
        String serialized = target.convertToDatabaseColumn(original);
        AbstractCredentialPublicKeyVO deserialized = target.convertToEntityAttribute(serialized);
        assertThat(deserialized).isEqualTo(deserialized);
    }

    @Test
    public void testRSCredentialPublicKeyVO(){
        RSCredentialPublicKeyVO original= new RSCredentialPublicKeyVO();
        original.setAlgorithm(RSSignatureAlgorithm.SHA256withRSA);
        original.setE(new byte[]{0b00, 0b01});
        original.setN(new byte[]{0b10, 0b11});
        String serialized = target.convertToDatabaseColumn(original);
        AbstractCredentialPublicKeyVO deserialized = target.convertToEntityAttribute(serialized);
        assertThat(deserialized).isEqualTo(deserialized);
    }
}
