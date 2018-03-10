package net.sharplab.springframework.security.webauthn.sample.domain.config;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.converter.*;
import net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.provider.PageImplProvider;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

/**
 * ModelMapper Configuration
 */
@Configuration
public class ModelMapperConfig {


    @Bean
    public ModelMapper modelMapper(){
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.addConverter(new AttestationStatementToAttestationStatementVOConverter());
        modelMapper.addConverter(new AttestationStatementVOToAttestationStatementConverter());
        modelMapper.addConverter(new CredentialPublicKeyToCredentialPublicKeyVOConverter());
        modelMapper.addConverter(new CredentialPublicKeyVOToCredentialPublicKeyConverter());
        modelMapper.addConverter(new PageImplConverter<UserEntity, User>(modelMapper));
        modelMapper.addConverter(new StringToChallengeConverter());
        modelMapper.addConverter(new UserToUserEntityConverter());
        modelMapper.createTypeMap(Page.class, PageImpl.class).setProvider(new PageImplProvider());
        modelMapper.getTypeMap(PageImpl.class, PageImpl.class).setProvider(new PageImplProvider());
        return modelMapper;
    }


    /**
     * creates ModelMapper instance
     * @return ModelMapper
     */
    public static ModelMapper createModelMapper(){
        return new ModelMapperConfig().modelMapper();
    }

}
