package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserPasswordForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Converter which converts from {@link UserPasswordForm} to {@link User}
 */
public class UserPasswordFormToUserConverter implements Converter<UserPasswordForm, User> {

    private PasswordEncoder passwordEncoder;

    public UserPasswordFormToUserConverter(PasswordEncoder passwordEncoder) {
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
    public User convert(MappingContext<UserPasswordForm, User> context) {

        UserPasswordForm source = context.getSource();
        User destination = context.getDestination();
        if (destination == null) {
            destination = new User();
        }

        // carry password only. No need to carry emailAddress.
        destination.setPassword(passwordEncoder.encode(source.getRawPassword()));

        return destination;
    }
}
