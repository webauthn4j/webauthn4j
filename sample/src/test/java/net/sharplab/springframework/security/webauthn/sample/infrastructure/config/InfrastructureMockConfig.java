package net.sharplab.springframework.security.webauthn.sample.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Created by ynojima on 2017/07/08.
 */
@Configuration
@Import(value = {JpaMockConfig.class})
public class InfrastructureMockConfig {


}
