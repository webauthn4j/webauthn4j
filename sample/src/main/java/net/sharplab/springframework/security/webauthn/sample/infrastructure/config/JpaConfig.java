package net.sharplab.springframework.security.webauthn.sample.infrastructure.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;

/**
 * JPA設定
 */
@Configuration
@EntityScan("net.sharplab.springframework.security.webauthn.sample.domain.entity")
public class JpaConfig {
}
