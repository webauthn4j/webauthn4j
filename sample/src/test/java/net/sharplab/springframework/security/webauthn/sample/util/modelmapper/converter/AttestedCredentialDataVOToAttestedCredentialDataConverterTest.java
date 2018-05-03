package net.sharplab.springframework.security.webauthn.sample.util.modelmapper.converter;

import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestedCredentialDataVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.CredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ESCredentialPublicKeyVO;
import org.junit.Test;
import org.modelmapper.ModelMapper;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestedCredentialDataVOToAttestedCredentialDataConverterTest {

    @Test
    public void test(){
        ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

        //Given
        byte[] aaGuid = new byte[16];
        byte[] credentialId = new byte[32];
        CredentialPublicKeyVO credentialPublicKey = new ESCredentialPublicKeyVO();
        AttestedCredentialDataVO source = new AttestedCredentialDataVO();
        source.setAaGuid(aaGuid);
        source.setCredentialId(credentialId);
        source.setCredentialPublicKey(credentialPublicKey);

        AttestedCredentialData destination = new AttestedCredentialData();


        //When
        modelMapper.map(source, destination);

        //Then
        assertThat(destination.getAaGuid()).isNotNull();
        assertThat(destination.getCredentialId()).isNotNull();
        assertThat(destination.getCredentialPublicKey()).isNotNull();

    }
}
