package com.webauthn4j.validator;

import com.webauthn4j.client.TokenBinding;
import com.webauthn4j.client.TokenBindingStatus;
import com.webauthn4j.validator.exception.TokenBindingException;
import org.junit.Test;

public class TokenBindingValidatorTest {

    private TokenBindingValidator target = new TokenBindingValidator();

    @Test
    public void validate_test() {
        byte[] bindingId = new byte[]{0x01, 0x23, 0x45};
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, bindingId);
        target.validate(tokenBinding, bindingId);
    }

    @Test(expected = TokenBindingException.class)
    public void validate_invalid_bindingId_test() {
        byte[] bindingId = new byte[]{0x01, 0x23, 0x45};
        byte[] invalidBindingId = new byte[]{0x00, 0x00, 0x00};
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, bindingId);
        target.validate(tokenBinding, invalidBindingId);
    }

    @Test
    public void validate_TokenBinding_not_supported_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.NOT_SUPPORTED, bindingId);
        target.validate(tokenBinding, bindingId);
    }

    @Test
    public void validate_TokenBinding_supported_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.SUPPORTED, bindingId);
        target.validate(tokenBinding, bindingId);
    }

}
