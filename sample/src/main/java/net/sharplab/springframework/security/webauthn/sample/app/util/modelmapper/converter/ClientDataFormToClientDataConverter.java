package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.sample.app.web.ClientDataForm;
import org.modelmapper.AbstractConverter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class ClientDataFormToClientDataConverter extends AbstractConverter<ClientDataForm, ClientData> {
    @Override
    protected ClientData convert(ClientDataForm source) {
        return source.getClientData();
    }
}
