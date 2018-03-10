package net.sharplab.thymeleaf.dialect;

import net.sharplab.thymeleaf.dialect.processor.ChallengeAttrProcessor;
import org.thymeleaf.dialect.AbstractDialect;
import org.thymeleaf.processor.IProcessor;

import java.util.LinkedHashSet;
import java.util.Set;

public class WebAuthnDialect extends AbstractDialect {

    public static final String DEFAULT_PREFIX = "webauthn";

    private String prefix = DEFAULT_PREFIX;

    public WebAuthnDialect(){
    }

    public WebAuthnDialect(String prefix){
        this.prefix = prefix;
    }

    @Override
    public String getPrefix() {
        return prefix;
    }

    @Override
    public Set<IProcessor> getProcessors() {
        final Set<IProcessor> processors = new LinkedHashSet<>();
        processors.add(new ChallengeAttrProcessor());
        return processors;
    }
}
