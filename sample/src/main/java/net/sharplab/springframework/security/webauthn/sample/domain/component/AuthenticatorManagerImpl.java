package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Created by ynojima on 2017/08/18.
 */
@Component
@Transactional
public class AuthenticatorManagerImpl implements AuthenticatorManager {
    ModelMapper modelMapper;

    private AuthenticatorEntityRepository authenticatorEntityRepository;

    /**
     * {@inheritDoc}
     */
    @Autowired
    public AuthenticatorManagerImpl(ModelMapper mapper, AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.modelMapper = mapper;
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public WebAuthnAuthenticator loadWebAuthnAuthenticatorByCredentialId(byte[] credentialId) {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId);
        if(authenticatorEntity == null){
            throw new CredentialIdNotFoundException(String.format("User with credentialId'%s' is not found.", credentialId));
        }
        return modelMapper.map(authenticatorEntity, Authenticator.class);
    }

}
