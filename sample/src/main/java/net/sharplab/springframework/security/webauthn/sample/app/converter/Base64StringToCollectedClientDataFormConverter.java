package net.sharplab.springframework.security.webauthn.sample.app.converter;

import net.sharplab.springframework.security.webauthn.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToCollectedClientDataConverter;
import net.sharplab.springframework.security.webauthn.sample.app.web.CollectedClientDataForm;
import org.springframework.core.convert.converter.Converter;

/**
 * Created by ynojima on 2017/08/20.
 */
public class Base64StringToCollectedClientDataFormConverter implements Converter<String, CollectedClientDataForm> {

    private Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter;

    public Base64StringToCollectedClientDataFormConverter(Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter){
        this.base64StringToCollectedClientDataConverter = base64StringToCollectedClientDataConverter;
    }

    @Override
    public CollectedClientDataForm convert(String source) {
        CollectedClientData collectedClientData = base64StringToCollectedClientDataConverter.convert(source);
        CollectedClientDataForm collectedClientDataForm = new CollectedClientDataForm();
        collectedClientDataForm.setCollectedClientData(collectedClientData);
        collectedClientDataForm.setClientDataBase64(source);
        return collectedClientDataForm;
    }
}
