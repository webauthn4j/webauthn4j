package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens.AuthenticatorEntityList;
import static net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens.AuthorityEntityList;
import static net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens.GroupEntityList;

/**
 * Converter which converts from {@link User} to {@link UserEntity}
 */
public class UserToUserEntityConverter implements Converter<User, UserEntity> {

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public UserEntity convert(MappingContext<User, UserEntity> context) {
        User source = context.getSource();
        UserEntity destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (destination == null) {
            destination = new UserEntity();
        }

        destination.setId(source.getId());
        destination.setUserHandle(source.getUserHandle());
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        if (source.getAuthorities() == null) {
            destination.setAuthorities(null);
        } else {
            destination.setAuthorities(context.getMappingEngine().map(context.create(source.getAuthorities(), AuthorityEntityList)));
        }
        if (source.getGroups() == null) {
            destination.setGroups(null);
        } else {
            destination.setGroups(context.getMappingEngine().map(context.create(source.getGroups(), GroupEntityList)));
        }
        destination.setPassword(source.getPassword());

        if (source.getAuthenticators() == null) {
            destination.setAuthenticators(null);
        } else {
            convertAuthenticators(context, source, destination);
        }

        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        destination.setLocked(source.isLocked());

        return destination;
    }

    //TODO:polish code
    private void convertAuthenticators(MappingContext<User, UserEntity> context, User srcUser, UserEntity dstUserEntity) {
        if (dstUserEntity.getAuthenticators() == null) {
            dstUserEntity.setAuthenticators(new ArrayList<>());
        }

        List<Authenticator> srcAuthenticators = new ArrayList<>(srcUser.getAuthenticators());
        List<AuthenticatorEntity> dstAuthenticators = dstUserEntity.getAuthenticators();
        List<AuthenticatorEntity> toBeRemoved = new ArrayList<>();

        dstAuthenticators.forEach(dstAuthenticatorEntity -> {
            Authenticator matchedSrcAuthenticator = null;
            for (Authenticator srcAuthenticator : srcAuthenticators) {
                if (Objects.equals(dstAuthenticatorEntity.getId(), srcAuthenticator.getId())) {
                    matchedSrcAuthenticator = srcAuthenticator;
                    break;
                }
            }
            if (matchedSrcAuthenticator == null) {
                toBeRemoved.add(dstAuthenticatorEntity);
                dstAuthenticatorEntity.setUser(null);
            } else {
                context.getMappingEngine().map(context.create(matchedSrcAuthenticator, dstAuthenticatorEntity));
                srcAuthenticators.remove(matchedSrcAuthenticator);
            }
        });
        for (Authenticator srcAuthenticator : srcAuthenticators) {
            AuthenticatorEntity dstAuthenticator = context.getMappingEngine().map(context.create(srcAuthenticator, AuthenticatorEntity.class));
            dstAuthenticator.setUser(dstUserEntity);
            dstAuthenticators.add(dstAuthenticator);
        }
        dstAuthenticators.removeAll(toBeRemoved);
    }
}
