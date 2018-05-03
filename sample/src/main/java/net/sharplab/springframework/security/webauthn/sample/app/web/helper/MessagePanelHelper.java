package net.sharplab.springframework.security.webauthn.sample.app.web.helper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;
import org.terasoluna.gfw.common.message.ResultMessage;
import org.terasoluna.gfw.common.message.ResultMessageUtils;

import java.util.Locale;

/**
 * MessagePanelHelper
 */
@Component
public class MessagePanelHelper {

    private final MessageSource messageSource;

    @Autowired
    public MessagePanelHelper(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    public String resolveMessage(ResultMessage resultMessage, Locale locale) {
        return ResultMessageUtils.resolveMessage(resultMessage, messageSource, locale);
    }

}
