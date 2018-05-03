package net.sharplab.springframework.security.webauthn.sample.domain.component;

import com.webauthn4j.authenticator.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

/**
 * {@inheritDoc}
 */
@Component
@Transactional
public class UserManagerImpl implements UserManager, WebAuthnUserDetailsService {

    ModelMapper modelMapper;

    private UserEntityRepository userEntityRepository;
    private AuthenticatorEntityRepository authenticatorEntityRepository;

    @Autowired
    public UserManagerImpl(ModelMapper mapper, UserEntityRepository userEntityRepository, AuthenticatorEntityRepository authenticatorEntityRepository) {
        this.modelMapper = mapper;
        this.userEntityRepository = userEntityRepository;
        this.authenticatorEntityRepository = authenticatorEntityRepository;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User findById(int id) {
        UserEntity userEntity = userEntityRepository.findById(id)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));
        return modelMapper.map(userEntity, User.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public WebAuthnUserDetails loadUserByUsername(String username) {
        UserEntity userEntity = userEntityRepository.findOneByEmailAddress(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User with username'%s' is not found.", username)));
        return modelMapper.map(userEntity, User.class);
    }

    @Override
    public WebAuthnUserDetails loadUserByAuthenticator(Authenticator authnAuthenticator) {
        AuthenticatorEntity authenticatorEntity = authenticatorEntityRepository.findOneByCredentialId(authnAuthenticator.getAttestedCredentialData().getCredentialId());
        return modelMapper.map(authenticatorEntity.getUser(), User.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User createUser(User user) {
        userEntityRepository.findOneByEmailAddress(user.getEmailAddress()).ifPresent((retrievedUserEntity) -> {
            throw new WebAuthnSampleBusinessException(ResultMessages.error().add(MessageCodes.Error.User.EMAIL_ADDRESS_IS_ALREADY_USED));
        });

        UserEntity userEntity = modelMapper.map(user, UserEntity.class);
        UserEntity createdUserEntity = userEntityRepository.save(userEntity);
        return modelMapper.map(createdUserEntity, User.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateUser(User user) {

        UserEntity userEntity = userEntityRepository.findById(user.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));
        modelMapper.map(user, userEntity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteUser(String username) {
        UserEntity userEntity = userEntityRepository.findOneByEmailAddress(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User with username'%s' is not found.", username)));
        userEntityRepository.delete(userEntity);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteUser(int id) {
        UserEntity userEntity = userEntityRepository.findById(id)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));
        userEntityRepository.deleteById(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void changePassword(String oldPassword, String newPassword) {
        User currentUser = getCurrentUser();

        if (currentUser == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException(
                    "Can't change rawPassword as no Authentication object found in context "
                            + "for current user.");
        }

        currentUser.setPassword(newPassword);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean userExists(String username) {
        return userEntityRepository.findOneByEmailAddress(username).isPresent();
    }

    /**
     * 現在のユーザーを返却する
     *
     * @return ユーザー
     */
    private User getCurrentUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
