package net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.ESCredentialPublicKey;
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
        source.setAlgorithm(-7);
        source.setX(new byte[]{0x00, 0x01});
        source.setY(new byte[]{0x02, 0x03});
        AbstractCredentialPublicKey destination = new ESCredentialPublicKey();

        //When
        modelMapper.map(source, destination);

        //Then
        assertThat(destination).hasFieldOrPropertyWithValue("algorithm", -7);
        assertThat(destination).hasFieldOrPropertyWithValue("x", new byte[]{0x00, 0x01});
        assertThat(destination).hasFieldOrPropertyWithValue("y", new byte[]{0x02, 0x03});
    }
}
