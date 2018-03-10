package net.sharplab.springframework.security.webauthn.sample.infrastructure.config;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Created by ynojima on 2017/08/12.
 */
@Configuration
@EnableAutoConfiguration
@Import(value = JpaConfig.class)
public class InfrastructureConfig {
}
