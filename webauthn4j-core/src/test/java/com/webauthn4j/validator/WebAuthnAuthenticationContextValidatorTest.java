package com.webauthn4j.validator;

import com.webauthn4j.validator.assertion.signature.AssertionSignatureValidator;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAuthenticationContextValidatorTest {

    @Test
    public void getter_setter_test(){
        WebAuthnAuthenticationContextValidator target = new WebAuthnAuthenticationContextValidator(mock(AssertionSignatureValidator.class));

        MaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultMaliciousCounterValueHandler();
        target.setMaliciousCounterValueHandler(maliciousCounterValueHandler);
        assertThat(target.getMaliciousCounterValueHandler()).isEqualTo(maliciousCounterValueHandler);

    }
}
