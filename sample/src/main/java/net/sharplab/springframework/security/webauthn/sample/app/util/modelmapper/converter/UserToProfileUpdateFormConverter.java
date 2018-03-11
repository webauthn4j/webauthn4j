package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;

import static net.sharplab.springframework.security.webauthn.sample.app.constant.AppTypeTokens.AuthenticatorFormList;

/**
 * Converter which converts from {@link User} to {@link ProfileUpdateForm}
 */
public class UserToProfileUpdateFormConverter implements Converter<User, ProfileUpdateForm> {

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public ProfileUpdateForm convert(MappingContext<User, ProfileUpdateForm> context) {
        ProfileUpdateForm destination = context.getDestination();
        if(destination == null){
            destination = new ProfileUpdateForm();
        }
        User source = context.getSource();

        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        if(source.getAuthenticators() == null){
            destination.setAuthenticators(null);
        }
        else {
            destination.setAuthenticators(context.getMappingEngine().map(context.create(source.getAuthenticators(), AuthenticatorFormList)));
        }
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        return destination;
    }
}
