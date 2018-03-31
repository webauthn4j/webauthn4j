package net.sharplab.springframework.security.webauthn.sample.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
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
