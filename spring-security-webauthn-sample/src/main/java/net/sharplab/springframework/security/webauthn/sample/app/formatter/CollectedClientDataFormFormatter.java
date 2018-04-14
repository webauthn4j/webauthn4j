package net.sharplab.springframework.security.webauthn.sample.app.formatter;

import com.webauthn4j.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToCollectedClientDataConverter;
import net.sharplab.springframework.security.webauthn.sample.app.web.CollectedClientDataForm;
import org.springframework.format.Formatter;

import java.text.ParseException;
import java.util.Locale;

/**
 * Converter which converts from {@link CollectedClientDataForm} to {@link String}
 */
public class CollectedClientDataFormFormatter implements Formatter<CollectedClientDataForm> {

    private Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter;

    public CollectedClientDataFormFormatter(Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter) {
        this.base64StringToCollectedClientDataConverter = base64StringToCollectedClientDataConverter;
    }

    @Override
    public CollectedClientDataForm parse(String text, Locale locale) throws ParseException {
        CollectedClientData collectedClientData = base64StringToCollectedClientDataConverter.convert(text);
        CollectedClientDataForm collectedClientDataForm = new CollectedClientDataForm();
        collectedClientDataForm.setCollectedClientData(collectedClientData);
        collectedClientDataForm.setClientDataBase64(text);
        return collectedClientDataForm;
    }

    @Override
    public String print(CollectedClientDataForm object, Locale locale) {
        return object.getClientDataBase64();
    }
}
