package net.sharplab.thymeleaf.dialect;

import net.sharplab.thymeleaf.dialect.processor.ChallengeAttrProcessor;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnDialectTest {

    @Test
    public void initialize_with_prefix(){
        WebAuthnDialect target = new WebAuthnDialect("prefix");
        assertThat(target.getPrefix()).isEqualTo("prefix");
        assertThat(target.getProcessors()).hasSize(1);
        assertThat(target.getProcessors()).first().isInstanceOf(ChallengeAttrProcessor.class);
    }

    @Test
    public void initialize_without_prefix(){
        WebAuthnDialect target = new WebAuthnDialect();
        assertThat(target.getPrefix()).isEqualTo("webauthn");
        assertThat(target.getProcessors()).hasSize(1);
        assertThat(target.getProcessors()).first().isInstanceOf(ChallengeAttrProcessor.class);
    }

}
