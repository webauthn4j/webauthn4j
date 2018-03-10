package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.AuthorityForm;
import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;

/**
 * Converter which converts from {@link AuthenticatorForm} to {@link AuthorityUpdateDto}
 */
public class AuthorityFormToAuthorityUpdateDtoConverter implements Converter<AuthorityForm, AuthorityUpdateDto> {

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public AuthorityUpdateDto convert(MappingContext<AuthorityForm, AuthorityUpdateDto> context) {
        AuthorityForm source = context.getSource();
        AuthorityUpdateDto destination = context.getDestination();
        if(destination == null){
            destination = new AuthorityUpdateDto();
        }
        int[] users  = source.getUsers();
        int[] groups = source.getGroups();
        destination.setUsers(users   == null ? new int[0] : users);
        destination.setGroups(groups == null ? new int[0] : groups);
        return destination;
    }
}
