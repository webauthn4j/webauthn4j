package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper;

import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.AuthorityForm;
import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;

import java.util.Collections;
import java.util.List;

/**
 * Converter which converts from {@link AuthenticatorCreateForm} to {@link AuthorityUpdateDto}
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
        if (destination == null) {
            destination = new AuthorityUpdateDto();
        }
        List<Integer> users = source.getUsers();
        List<Integer> groups = source.getGroups();
        destination.setUsers(users == null ? Collections.emptyList() : users);
        destination.setGroups(groups == null ? Collections.emptyList() : groups);
        return destination;
    }
}
