package net.sharplab.thymeleaf.dialect.processor;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ChallengeAttrProcessorTest {

    private ChallengeAttrProcessor target = new ChallengeAttrProcessor();

    @Test
    public void test(){
        assertThat(target.getPrecedence()).isZero();
        assertThat(target.getTargetAttributeName(null,null,null)).isEqualTo("content");
        //assertThat(target.getTargetAttributeValue(arguments, null, null));
    }

}
