package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.converter.Base64StringToCollectedClientDataConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToWebAuthnAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.AttestationObjectFormToBase64StringConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.Base64StringToAttestationObjectFormConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.Base64StringToCollectedClientDataFormConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Conversion Service Configuration
 */
@Configuration
public class ConverterConfig {

    @Bean
    public AttestationObjectFormToBase64StringConverter attestationObjectFormToBase64StringConverter() {
        return new AttestationObjectFormToBase64StringConverter();
    }

    @Bean
    public Base64StringToCollectedClientDataConverter stringToCollectedClientDataConverter() {
        return new Base64StringToCollectedClientDataConverter();
    }

    @Bean
    public Base64StringToWebAuthnAttestationObjectConverter stringToWebAuthnAttestationObjectConverter() {
        return new Base64StringToWebAuthnAttestationObjectConverter();
    }

    @Bean
    public Base64StringToCollectedClientDataFormConverter stringToCollectedClientDataFormConverter(Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter) {
        return new Base64StringToCollectedClientDataFormConverter(base64StringToCollectedClientDataConverter);
    }

    @Bean
    public Base64StringToAttestationObjectFormConverter stringToAttestationObjectFormConverter(Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter) {
        return new Base64StringToAttestationObjectFormConverter(base64StringToWebAuthnAttestationObjectConverter);
    }

}
