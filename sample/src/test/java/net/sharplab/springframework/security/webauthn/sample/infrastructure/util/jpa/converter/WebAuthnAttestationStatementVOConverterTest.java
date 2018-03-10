package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.FIDOU2FAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.PackedAttestationStatementVO;
import org.junit.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by ynojima on 2017/08/11.
 */
public class WebAuthnAttestationStatementVOConverterTest {

    private AttestationStatementVOConverter target = new AttestationStatementVOConverter();

    @Test
    public void testFIDOU2FAttestationStatementVO(){
        FIDOU2FAttestationStatementVO original= new FIDOU2FAttestationStatementVO();
        original.setSig(new byte[]{0b00, 0b01});
        original.setX5c(Arrays.asList(new byte[]{0b10, 0b11}));
        String serialized = target.convertToDatabaseColumn(original);
        AttestationStatementVO deserialized = target.convertToEntityAttribute(serialized);
        assertThat(deserialized).isEqualTo(deserialized);
    }

    @Test
    public void testPackedAttestationStatementVO(){
        PackedAttestationStatementVO original= new PackedAttestationStatementVO();
        //original.setAlg(); //TODO
        //original.setEcdaaKeyId(); //TODO
        original.setSig(new byte[]{0b00, 0b01});
        original.setX5c(Arrays.asList(new byte[]{0b10, 0b11}));
        String serialized = target.convertToDatabaseColumn(original);
        AttestationStatementVO deserialized = target.convertToEntityAttribute(serialized);
        assertThat(deserialized).isEqualTo(deserialized);
    }


}
