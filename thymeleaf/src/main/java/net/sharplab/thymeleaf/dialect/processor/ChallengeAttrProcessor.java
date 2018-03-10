package net.sharplab.thymeleaf.dialect.processor;

import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.client.challenge.ChallengeRepository;
import org.apache.commons.codec.binary.Base64;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Base64Utils;
import org.thymeleaf.Arguments;
import org.thymeleaf.context.IContext;
import org.thymeleaf.dom.Element;
import org.thymeleaf.exceptions.ConfigurationException;
import org.thymeleaf.processor.attr.AbstractSingleAttributeModifierAttrProcessor;
import org.thymeleaf.spring4.context.SpringWebContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ChallengeAttrProcessor extends AbstractSingleAttributeModifierAttrProcessor {

    public static final int ATTR_PRECEDENCE = 0;
    public static final String ATTR_NAME = "challenge";
    public static final String TARGET_ATTR_NAME = "content";

    public ChallengeAttrProcessor() {
        super(ATTR_NAME);
    }

    @Override
    public int getPrecedence() {
        return ATTR_PRECEDENCE;
    }

    @Override
    protected String getTargetAttributeName(Arguments arguments, Element element, String attributeName) {
        return TARGET_ATTR_NAME;
    }

    @Override
    protected String getTargetAttributeValue(Arguments arguments, Element element, String attributeName) {

        Challenge challenge = getChallenge(arguments);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());
    }

    @Override
    protected ModificationType getModificationType(Arguments arguments, Element element, String attributeName, String newAttributeName) {
        return ModificationType.SUBSTITUTION;
    }

    @Override
    protected boolean removeAttributeIfEmpty(Arguments arguments, Element element, String attributeName, String newAttributeName) {
        return false;
    }

    @Override
    protected boolean recomputeProcessorsAfterExecution(Arguments arguments, Element element, String attributeName) {
        return false;
    }

    private Challenge getChallenge(Arguments arguments){
        IContext context = arguments.getContext();
        if (!(context instanceof SpringWebContext)) {
            throw new ConfigurationException(
                    "Thymeleaf execution context is not a web context (implementation of " +
                            SpringWebContext.class.getName() + ". Spring Security integration can only be used in " +
                            "web environements.");
        }
        SpringWebContext springWebContext = (SpringWebContext) context;
        ApplicationContext applicationContext = springWebContext.getApplicationContext();
        HttpServletRequest httpServletRequest = springWebContext.getHttpServletRequest();
        HttpServletResponse httpServletResponse = springWebContext.getHttpServletResponse();
        ChallengeRepository challengeRepository = applicationContext.getBean(ChallengeRepository.class);
        Challenge challenge = challengeRepository.loadChallenge(httpServletRequest);
        if(challenge == null){
            challenge = challengeRepository.generateChallenge();
            challengeRepository.saveChallenge(challenge, httpServletRequest, httpServletResponse);
        }
        return challenge;
    }
}
