package net.sharplab.thymeleaf.dialect;

import net.sharplab.thymeleaf.dialect.processor.ChallengeAttrProcessor;
import org.thymeleaf.dialect.AbstractDialect;
import org.thymeleaf.dialect.IProcessorDialect;
import org.thymeleaf.processor.IProcessor;

import java.util.LinkedHashSet;
import java.util.Set;

public class WebAuthnDialect extends AbstractDialect implements IProcessorDialect {

    public static final String NAME = "webauthn";
    public static final String DEFAULT_PREFIX = "webauthn";
    public static final int PROCESSOR_PRECEDENCE = 800;

    private String prefix = DEFAULT_PREFIX;

    public WebAuthnDialect() {
        super(NAME);
    }

    public WebAuthnDialect(String prefix) {
        super(NAME);
        this.prefix = prefix;
    }

    @Override
    public String getPrefix() {
        return prefix;
    }

    @Override
    public int getDialectProcessorPrecedence() {
        return PROCESSOR_PRECEDENCE;
    }

    @Override
    public Set<IProcessor> getProcessors(String dialectPrefix) {
        final Set<IProcessor> processors = new LinkedHashSet<>();
        processors.add(new ChallengeAttrProcessor(getPrefix(), getDialectProcessorPrecedence()));
        return processors;
    }

}
