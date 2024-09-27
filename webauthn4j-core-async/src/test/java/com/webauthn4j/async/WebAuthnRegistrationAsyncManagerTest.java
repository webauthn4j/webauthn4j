package com.webauthn4j.async;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

class WebAuthnRegistrationAsyncManagerTest {

    @Test
    void createNonStrictWebAuthnRegistrationAsyncManager_test(){
        assertThatCode(WebAuthnRegistrationAsyncManager::createNonStrictWebAuthnRegistrationAsyncManager).doesNotThrowAnyException();
    }

}