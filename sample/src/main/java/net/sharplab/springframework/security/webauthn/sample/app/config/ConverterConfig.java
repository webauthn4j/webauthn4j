package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.converter.Base64StringToClientDataConverter;
import net.sharplab.springframework.security.webauthn.converter.WebAuthnAttestationObjectToBase64StringConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToWebAuthnAttestationObjectConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.AttestationObjectFormToBase64StringConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.Base64StringToAttestationObjectFormConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.Base64StringToClientDataFormConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Conversion Service Configuration
 */
@Configuration
public class ConverterConfig {

    @Bean
    public AttestationObjectFormToBase64StringConverter attestationObjectFormToBase64StringConverter(){
        return new AttestationObjectFormToBase64StringConverter();
    }

    @Bean
    public Base64StringToClientDataConverter stringToClientDataConverter(){
        return new Base64StringToClientDataConverter();
    }

    @Bean
    public Base64StringToWebAuthnAttestationObjectConverter stringToWebAuthnAttestationObjectConverter(){
        return new Base64StringToWebAuthnAttestationObjectConverter();
    }

    @Bean
    public Base64StringToClientDataFormConverter stringToClientDataFormConverter(Base64StringToClientDataConverter base64StringToClientDataConverter){
        return new Base64StringToClientDataFormConverter(base64StringToClientDataConverter);
    }

    @Bean
    public Base64StringToAttestationObjectFormConverter stringToAttestationObjectFormConverter(Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter){
        return new Base64StringToAttestationObjectFormConverter(base64StringToWebAuthnAttestationObjectConverter);
    }

}
