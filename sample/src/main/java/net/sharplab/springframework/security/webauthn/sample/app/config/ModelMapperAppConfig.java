package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.AttestationObjectFormToAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.AuthorityFormToAuthorityUpdateDtoConverter;
import net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.AuthorityToAuthorityFormConverter;
import net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.ClientDataFormToClientDataConverter;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import javax.annotation.PostConstruct;

/**
 * ModelMapper Configuration
 */
@SuppressWarnings("SpringAutowiredFieldsWarningInspection")
@Configuration
@Import(ModelMapperConfig.class)
@ComponentScan(basePackages = "net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter")
public class ModelMapperAppConfig {

    @Autowired
    ModelMapper modelMapper;

    @PostConstruct
    public void initialize() {
        modelMapper.addConverter(new AuthorityToAuthorityFormConverter());
        modelMapper.addConverter(new AuthorityFormToAuthorityUpdateDtoConverter());
        modelMapper.addConverter(new AttestationObjectFormToAttestationObjectConverter());
        modelMapper.addConverter(new ClientDataFormToClientDataConverter());
    }

}
