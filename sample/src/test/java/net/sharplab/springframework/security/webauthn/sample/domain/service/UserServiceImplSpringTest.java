package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@Import({DomainConfig.class, InfrastructureMockConfig.class})
public class UserServiceImplSpringTest {

    @Test
    public void test(){

    }
}
