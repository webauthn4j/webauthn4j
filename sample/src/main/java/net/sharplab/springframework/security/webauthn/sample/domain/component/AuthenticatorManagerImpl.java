package net.sharplab.springframework.security.webauthn.sample.domain.component;

import com.webauthn4j.authenticator.Authenticator;
import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;

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
    public Authenticator loadWebAuthnAuthenticatorByCredentialId(byte[] credentialId) {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(credentialId);
        if (authenticatorEntity == null) {
            throw new CredentialIdNotFoundException(String.format("User with credentialId'%s' is not found.", new String(credentialId, StandardCharsets.UTF_8)));
        }
        return modelMapper.map(authenticatorEntity, net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator.class);
    }

}
