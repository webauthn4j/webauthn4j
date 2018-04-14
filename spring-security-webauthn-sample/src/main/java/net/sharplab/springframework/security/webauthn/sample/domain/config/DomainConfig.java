package net.sharplab.springframework.security.webauthn.sample.domain.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.terasoluna.gfw.common.exception.ExceptionLogger;
import org.terasoluna.gfw.common.exception.ResultMessagesLoggingInterceptor;

/**
 * DomainConfig
 */
@Configuration
@ComponentScan("net.sharplab.springframework.security.webauthn.sample.domain")
public class DomainConfig {

    @Bean
    public ExceptionLogger exceptionLogger() {
        return new ExceptionLogger();
    }

    @Bean
    public ResultMessagesLoggingInterceptor resultMessagesLoggingInterceptor(ExceptionLogger exceptionLogger) {
        ResultMessagesLoggingInterceptor resultMessagesLoggingInterceptor = new ResultMessagesLoggingInterceptor();
        resultMessagesLoggingInterceptor.setExceptionLogger(exceptionLogger);
        return resultMessagesLoggingInterceptor;
    }

}
