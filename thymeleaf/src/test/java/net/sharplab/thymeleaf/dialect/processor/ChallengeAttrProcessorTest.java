package net.sharplab.thymeleaf.dialect.processor;

import org.junit.Test;
import org.thymeleaf.templatemode.TemplateMode;

import static org.assertj.core.api.Assertions.assertThat;

public class ChallengeAttrProcessorTest {

    private ChallengeAttrProcessor target = new ChallengeAttrProcessor("prefix", 10000);

    @Test
    public void test(){
        assertThat(target.getPrecedence()).isEqualTo(10000);
        assertThat(target.getTemplateMode()).isEqualTo(TemplateMode.HTML);
    }

}

