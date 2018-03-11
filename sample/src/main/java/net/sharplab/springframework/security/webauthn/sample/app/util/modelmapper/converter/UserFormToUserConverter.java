package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Base64Utils;

import java.util.Collections;

import static net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens.AuthenticatorList;

/**
 * Converter which converts from {@link UserForm} to {@link User}
 */
public class UserFormToUserConverter implements Converter<UserForm, User> {

    private PasswordEncoder passwordEncoder;

    public UserFormToUserConverter(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public User convert(MappingContext<UserForm, User> context) {
        User destination = context.getDestination();
        if(destination == null){
            destination = new User();
        }
        UserForm source = context.getSource();

        destination.setUserHandle(Base64Utils.decodeFromUrlSafeString(source.getUserHandle()));
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        destination.setPassword(passwordEncoder.encode(source.getRawPassword()));
        if(source.getAuthenticators() == null){
            destination.setAuthenticators(Collections.emptyList());
        }
        else {
            destination.setAuthenticators(context.getMappingEngine().map(context.create(source.getAuthenticators(), AuthenticatorList)));
        }
        destination.setLocked(source.isLocked());
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        return destination;

    }
}
