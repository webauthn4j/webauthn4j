package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper;

import com.webauthn4j.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.sample.app.web.CollectedClientDataForm;
import org.modelmapper.AbstractConverter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class ClientDataFormToClientDataConverter extends AbstractConverter<CollectedClientDataForm, CollectedClientData> {
    @Override
    protected CollectedClientData convert(CollectedClientDataForm source) {
        return source.getCollectedClientData();
    }
}
