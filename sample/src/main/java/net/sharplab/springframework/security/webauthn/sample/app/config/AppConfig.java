package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.context.provider.WebAuthnRegistrationContextProvider;
import net.sharplab.springframework.security.webauthn.context.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.sample.app.web.UserHelper;
import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.terasoluna.gfw.common.exception.ExceptionLogger;
import org.terasoluna.gfw.web.exception.ExceptionLoggingFilter;
import org.terasoluna.gfw.web.exception.SystemExceptionResolver;


/**
 * Application Layer Configuration
 */
@Configuration
@Import({ConverterConfig.class, ModelMapperAppConfig.class})
@EnableSpringDataWebSupport
@ComponentScan(basePackages = "net.sharplab.springframework.security.webauthn.sample.app")
public class AppConfig {

    @Bean
    public ExceptionLoggingFilter exceptionLoggingFilter(ExceptionLogger exceptionLogger){
        ExceptionLoggingFilter exceptionLoggingFilter = new ExceptionLoggingFilter();
        exceptionLoggingFilter.setExceptionLogger(exceptionLogger);
        return exceptionLoggingFilter;
    }

    @Bean
    public UserHelper userHelper(WebAuthnRegistrationContextProvider webAuthnRegistrationContextProvider,
                                 WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator){
        return new UserHelper(webAuthnRegistrationContextProvider, webAuthnRegistrationContextValidator);
    }

}
