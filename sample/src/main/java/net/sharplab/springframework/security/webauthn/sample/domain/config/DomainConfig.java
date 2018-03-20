package net.sharplab.springframework.security.webauthn.sample.domain.config;

import net.sharplab.springframework.security.fido.metadata.CertPathJWSVerifier;
import net.sharplab.springframework.security.fido.metadata.FIDOMetadataServiceClient;
import net.sharplab.springframework.security.webauthn.anchor.FIDOMetadataServiceTrustAnchorService;
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
    public FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService(FIDOMetadataServiceClient fidoMetadataServiceClient) {
        return new FIDOMetadataServiceTrustAnchorService(fidoMetadataServiceClient);
    }

    @Bean
    public FIDOMetadataServiceClient fidoMetadataServiceClient(ResourceLoader resourceLoader) {
        return new FIDOMetadataServiceClient(new RestTemplate(), new CertPathJWSVerifier(resourceLoader)); //TODO use CertPathJWSVaerifier
    }

}
