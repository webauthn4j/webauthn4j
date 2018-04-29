package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;

import static net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens.*;

public class UserEntityToUserConverter implements Converter<UserEntity, User> {

    @Override
    public User convert(MappingContext<UserEntity, User> context) {
        UserEntity source = context.getSource();
        User destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (destination == null) {
            destination = new User();
        }

        destination.setId(source.getId());
        destination.setUserHandle(source.getUserHandle());
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        if (source.getAuthorities() == null) {
            destination.setAuthorities(null);
        } else {
            destination.setAuthorities(context.getMappingEngine().map(context.create(source.getAuthorities(), AuthorityList)));
        }
        if (source.getGroups() == null) {
            destination.setGroups(null);
        } else {
            destination.setGroups(context.getMappingEngine().map(context.create(source.getGroups(), GroupList)));
        }
        destination.setPassword(source.getPassword());

        if (source.getAuthenticators() == null) {
            destination.setAuthenticators(null);
        } else {
            destination.setAuthenticators(context.getMappingEngine().map(context.create(source.getAuthenticators(), AuthenticatorList)));
        }

        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        destination.setLocked(source.isLocked());

        return destination;
    }
}
