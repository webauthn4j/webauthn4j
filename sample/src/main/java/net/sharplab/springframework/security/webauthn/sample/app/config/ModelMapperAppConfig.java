package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter.*;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    @Autowired
    PasswordEncoder passwordEncoder;

    @PostConstruct
    public void initialize(){
        modelMapper.addConverter(new UserFormToUserConverter(passwordEncoder));
        modelMapper.addConverter(new UserUpdateFormToUserConverter());
        modelMapper.addConverter(new UserPasswordFormToUserConverter(passwordEncoder));
        modelMapper.addConverter(new UserToUserFormConverter());
        modelMapper.addConverter(new ProfileUpdateFormToUserConverter(passwordEncoder));
        modelMapper.addConverter(new UserToProfileUpdateFormConverter());
        modelMapper.addConverter(new AuthorityToAuthorityFormConverter());
        modelMapper.addConverter(new AuthorityFormToAuthorityUpdateDtoConverter());
        modelMapper.addConverter(new AuthenticatorFormToAuthenticatorConverter());
        modelMapper.addConverter(new AttestationObjectFormToWebAuthnAttestationObjectConverter());
        modelMapper.addConverter(new ClientDataFormToClientDataConverter());
    }

}
