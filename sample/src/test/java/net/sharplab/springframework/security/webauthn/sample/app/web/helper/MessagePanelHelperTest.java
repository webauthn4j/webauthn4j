package net.sharplab.springframework.security.webauthn.sample.app.web.helper;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.StaticMessageSource;
import org.terasoluna.gfw.common.message.ResultMessage;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for MessagePanelHelper
 */
public class MessagePanelHelperTest {

    private StaticMessageSource messageSource;
    private MessagePanelHelper target;

    @Before
    public void setup(){
        messageSource = new StaticMessageSource();
        messageSource.addMessage("messageCode", Locale.JAPAN, "Hello, {0}.");
        target = new MessagePanelHelper(messageSource);
    }

    @Test
    public void resolveMessage_test1(){
        String value = "John";
        ResultMessage resultMessage = ResultMessage.fromCode("messageCode", value);

        //Given

        //When
        String result = target.resolveMessage(resultMessage, Locale.JAPAN);

        //Then
        assertThat(result).isEqualTo("Hello, John.");
    }

}
