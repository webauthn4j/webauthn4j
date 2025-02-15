package com.webauthn4j.data.extension.client;

import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FIDOAppIDExclusionExtensionClientOutputTest {

    @Test
    void validate_test() {
        FIDOAppIDExclusionExtensionClientOutput target = new FIDOAppIDExclusionExtensionClientOutput(false);
        assertThatCode(target::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_invalid_data_test() {
        FIDOAppIDExclusionExtensionClientOutput target = new FIDOAppIDExclusionExtensionClientOutput(null);
        assertThatThrownBy(target::validate).isInstanceOf(ConstraintViolationException.class);
    }


}