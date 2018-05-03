package net.sharplab.springframework.security.webauthn.sample.util.modelmapper.converter;

import com.webauthn4j.attestation.authenticator.Curve;
import com.webauthn4j.attestation.authenticator.ESCredentialPublicKey;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ESCredentialPublicKeyVO;
import org.junit.Test;
import org.modelmapper.ModelMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for CredentialPublicKeyVOToCredentialPublicKeyConverter
 */
public class CredentialPublicKeyVOToCredentialPublicKeyConverterTest {

    @Test
    public void mapToExistingInstance_test(){
        ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

        //Given
        ESCredentialPublicKeyVO source = new ESCredentialPublicKeyVO();
        source.setAlgorithm(COSEAlgorithmIdentifier.ES256);
        source.setCurve(Curve.SECP256R1);
        source.setX(new byte[]{0x00, 0x01});
        source.setY(new byte[]{0x02, 0x03});
        ESCredentialPublicKey destination = new ESCredentialPublicKey();

        //When
        modelMapper.map(source, destination);

        //Then
        assertThat(destination).hasFieldOrPropertyWithValue("algorithm", COSEAlgorithmIdentifier.ES256);
        assertThat(destination).hasFieldOrPropertyWithValue("curve", Curve.SECP256R1);
        assertThat(destination).hasFieldOrPropertyWithValue("x", new byte[]{0x00, 0x01});
        assertThat(destination).hasFieldOrPropertyWithValue("y", new byte[]{0x02, 0x03});
    }
}
