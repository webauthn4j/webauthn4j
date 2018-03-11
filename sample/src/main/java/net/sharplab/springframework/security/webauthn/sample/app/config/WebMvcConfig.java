package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.sample.app.converter.AttestationObjectFormToBase64StringConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.Base64StringToAttestationObjectFormConverter;
import net.sharplab.springframework.security.webauthn.sample.app.converter.Base64StringToClientDataFormConverter;
import net.sharplab.thymeleaf.dialect.WebAuthnDialect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.server.i18n.AcceptHeaderLocaleContextResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import java.util.Locale;

/**
 * WebMVC Configuration
 */
@Import(ConverterConfig.class)
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Autowired
    private Base64StringToAttestationObjectFormConverter base64StringToAttestationObjectFormConverter;

    @Autowired
    private Base64StringToClientDataFormConverter base64StringToClientDataFormConverter;

    @Autowired
    private AttestationObjectFormToBase64StringConverter attestationObjectFormToBase64StringConverter;

    @Bean
    public LocaleResolver localeResolver(){
        AcceptHeaderLocaleResolver localeResolver = new AcceptHeaderLocaleResolver();
        localeResolver.setDefaultLocale(Locale.US);
        return localeResolver;
    }

    @Bean
    public WebAuthnDialect webAuthnDialect(){
        return new WebAuthnDialect();
    }

    @Override
    public void addFormatters(FormatterRegistry formatterRegistry)
    {
        formatterRegistry.addConverter(base64StringToAttestationObjectFormConverter);
        formatterRegistry.addConverter(base64StringToClientDataFormConverter);
        formatterRegistry.addConverter(attestationObjectFormToBase64StringConverter);
    }
}
