package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;
import org.springframework.util.Base64Utils;

import static net.sharplab.springframework.security.webauthn.sample.app.constant.AppTypeTokens.AuthenticatorFormList;

/**
 * Converter which converts from {@link User} to {@link UserForm}
 */
public class UserToUserFormConverter implements Converter<User, UserForm> {

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public UserForm convert(MappingContext<User, UserForm> context) {
        User source = context.getSource();
        UserForm destination = context.getDestination();
        if(destination == null){
            destination = new UserForm();
        }
        byte[] sourceUserHandle = source.getUserHandle();
        if(sourceUserHandle == null){
            destination.setUserHandle(null);
        }
        else {
            destination.setUserHandle(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sourceUserHandle));
        }
        destination.setFirstName(source.getFirstName());
        destination.setLastName(source.getLastName());
        destination.setEmailAddress(source.getEmailAddress());
        if(source.getAuthenticators() == null){
            destination.setAuthenticators(null);
        }
        else {
            destination.setAuthenticators(context.getMappingEngine().map(context.create(source.getAuthenticators(), AuthenticatorFormList)));
        }
        destination.setLocked(source.isLocked());
        destination.setPasswordAuthenticationAllowed(source.isPasswordAuthenticationAllowed());
        return destination;
    }
}
