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
public class CredentialPublicKeyToCredentialPublicKeyVOConverterTest {

    @Test
    public void mapToExistingInstance_test(){
        ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

        //Given
        ESCredentialPublicKey source = new ESCredentialPublicKey(
                0,
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                new byte[]{0x00, 0x01},
                new byte[]{0x02, 0x03},
                null
        );
        ESCredentialPublicKeyVO destination = new ESCredentialPublicKeyVO();

        //When
        modelMapper.map(source, destination);

        //Then
        assertThat(destination).hasFieldOrPropertyWithValue("algorithm", COSEAlgorithmIdentifier.ES256);
        assertThat(destination).hasFieldOrPropertyWithValue("curve", Curve.SECP256R1);
        assertThat(destination).hasFieldOrPropertyWithValue("x", new byte[]{0x00, 0x01});
        assertThat(destination).hasFieldOrPropertyWithValue("y", new byte[]{0x02, 0x03});
    }
}
