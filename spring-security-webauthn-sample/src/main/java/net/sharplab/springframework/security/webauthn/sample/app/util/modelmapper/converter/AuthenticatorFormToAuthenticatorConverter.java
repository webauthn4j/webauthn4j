package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.spi.MappingContext;

/**
 * Converter which converts from {@link AuthenticatorForm} to {@link Authenticator}
 */
public class AuthenticatorFormToAuthenticatorConverter implements Converter<AuthenticatorForm, Authenticator> {

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public Authenticator convert(MappingContext<AuthenticatorForm, Authenticator> context) {
        AuthenticatorForm source = context.getSource();
        Authenticator destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (destination == null) {
            destination = new Authenticator();
        }
        destination.setId(source.getId());
        destination.setName(source.getName());
        destination.setRpIdHash(source.getAttestationObject().getAttestationObject().getAuthenticatorData().getRpIdHash());
        destination.setCounter(source.getAttestationObject().getAttestationObject().getAuthenticatorData().getCounter());
        destination.setAttestationData(source.getAttestationObject().getAttestationObject().getAuthenticatorData().getAttestationData());
        destination.setAttestationStatement(source.getAttestationObject().getAttestationObject().getAttestationStatement());
        return destination;
    }

}
