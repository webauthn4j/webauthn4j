package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.context.provider.WebAuthnRegistrationContextProvider;
import net.sharplab.springframework.security.webauthn.context.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.sample.app.web.helper.AuthenticatorHelper;
import net.sharplab.springframework.security.webauthn.sample.app.web.helper.UserHelper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.terasoluna.gfw.common.exception.ExceptionLogger;
import org.terasoluna.gfw.web.exception.ExceptionLoggingFilter;


/**
 * Application Layer Configuration
 */
@Configuration
@Import({ConverterConfig.class, ModelMapperAppConfig.class})
@EnableSpringDataWebSupport
@ComponentScan(basePackages = "net.sharplab.springframework.security.webauthn.sample.app")
public class AppConfig {

    @Bean
    public ExceptionLoggingFilter exceptionLoggingFilter(ExceptionLogger exceptionLogger) {
        ExceptionLoggingFilter exceptionLoggingFilter = new ExceptionLoggingFilter();
        exceptionLoggingFilter.setExceptionLogger(exceptionLogger);
        return exceptionLoggingFilter;
    }

}
