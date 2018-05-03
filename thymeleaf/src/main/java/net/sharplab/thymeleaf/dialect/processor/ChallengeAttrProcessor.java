package net.sharplab.thymeleaf.dialect.processor;

import com.webauthn4j.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;
import org.springframework.context.ApplicationContext;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.context.IWebContext;
import org.thymeleaf.engine.AttributeName;
import org.thymeleaf.model.IProcessableElementTag;
import org.thymeleaf.processor.element.AbstractAttributeTagProcessor;
import org.thymeleaf.processor.element.IElementTagStructureHandler;
import org.thymeleaf.spring5.context.SpringContextUtils;
import org.thymeleaf.templatemode.TemplateMode;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ChallengeAttrProcessor extends AbstractAttributeTagProcessor {

    public static final String TARGET_ATTR_NAME = "content";

    public ChallengeAttrProcessor(String prefix, int precedence) {
        super(TemplateMode.HTML,
                prefix,
                "meta",
                false,
                "challenge",
                true,
                precedence,
                true);
    }

    @Override
    protected void doProcess(ITemplateContext context, IProcessableElementTag tag, AttributeName attributeName, String attributeValue, IElementTagStructureHandler structureHandler) {
        Challenge challenge = getChallenge(context);
        String challengeValue = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());
        structureHandler.setAttribute(TARGET_ATTR_NAME, challengeValue);
    }

    private Challenge getChallenge(ITemplateContext context) {
        ApplicationContext applicationContext = SpringContextUtils.getApplicationContext(context);
        IWebContext webContext = (IWebContext) context;
        HttpServletRequest httpServletRequest = webContext.getRequest();
        HttpServletResponse httpServletResponse = webContext.getResponse();
        ChallengeRepository challengeRepository = applicationContext.getBean(ChallengeRepository.class);
        Challenge challenge = challengeRepository.loadChallenge(httpServletRequest);
        if (challenge == null) {
            challenge = challengeRepository.generateChallenge();
            challengeRepository.saveChallenge(challenge, httpServletRequest, httpServletResponse);
        }
        return challenge;
    }
}
