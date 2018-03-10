package net.sharplab.springframework.security.webauthn.sample.app.converter;

import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToClientDataConverter;
import net.sharplab.springframework.security.webauthn.sample.app.web.ClientDataForm;
import org.springframework.core.convert.converter.Converter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class Base64StringToClientDataFormConverter implements Converter<String, ClientDataForm> {

    private Base64StringToClientDataConverter base64StringToClientDataConverter;

    public Base64StringToClientDataFormConverter(Base64StringToClientDataConverter base64StringToClientDataConverter){
        this.base64StringToClientDataConverter = base64StringToClientDataConverter;
    }

    @Override
    public ClientDataForm convert(String source) {
        ClientData clientData = base64StringToClientDataConverter.convert(source);
        ClientDataForm clientDataForm = new ClientDataForm();
        clientDataForm.setClientData(clientData);
        clientDataForm.setClientDataBase64(source);
        return clientDataForm;
    }
}
