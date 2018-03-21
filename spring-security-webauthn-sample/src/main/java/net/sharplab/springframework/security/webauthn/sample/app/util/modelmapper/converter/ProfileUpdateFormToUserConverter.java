package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;


import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens.AuthenticatorList;

/**
 * Converter which converts from {@link ProfileUpdateForm} to {@link User}
 */
public class ProfileUpdateFormToUserConverter implements Converter<ProfileUpdateForm, User> {

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public User convert(MappingContext<ProfileUpdateForm, User> context) {
        ProfileUpdateForm source = context.getSource();
        User destination = context.getDestination();
        if (destination == null) {
            destination = new User();
        }
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        if (source.getAuthenticators() == null) {
            destination.setAuthenticators(Collections.emptyList());
        } else {
            destination.setAuthenticators(context.getMappingEngine().map(context.create(source.getAuthenticators(), AuthenticatorList)));
        }
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());

        return destination;
    }
}
