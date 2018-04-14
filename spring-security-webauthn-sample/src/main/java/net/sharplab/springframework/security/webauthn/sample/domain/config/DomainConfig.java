package net.sharplab.springframework.security.webauthn.sample.domain.config;

import com.webauthn4j.extras.fido.metadata.CertPathJWSVerifier;
import com.webauthn4j.extras.fido.metadata.FIDOMetadataServiceClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.client.RestTemplate;
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

    @Bean
    public FIDOMetadataServiceClient fidoMetadataServiceClient(ResourceLoader resourceLoader) {
        return new FIDOMetadataServiceClient(new RestTemplate(), new CertPathJWSVerifier(resourceLoader)); //TODO use CertPathJWSVaerifier
    }

}
