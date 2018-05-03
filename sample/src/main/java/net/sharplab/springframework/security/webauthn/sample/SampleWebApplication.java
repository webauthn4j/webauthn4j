package net.sharplab.springframework.security.webauthn.sample;

import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * SampleWebApplication
 */
@Import({AppConfig.class, DomainConfig.class, InfrastructureConfig.class})
@SpringBootConfiguration
@EnableAutoConfiguration
public class SampleWebApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleWebApplication.class, args);
    }
}