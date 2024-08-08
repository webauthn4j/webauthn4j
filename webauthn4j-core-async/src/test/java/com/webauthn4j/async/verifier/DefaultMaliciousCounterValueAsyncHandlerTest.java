package com.webauthn4j.async.verifier;

import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class DefaultMaliciousCounterValueAsyncHandlerTest {

    @Test
    void test() {
        DefaultMaliciousCounterValueAsyncHandler target = new DefaultMaliciousCounterValueAsyncHandler();
        AuthenticationObject authenticationObject = mock(AuthenticationObject.class);
        assertThatThrownBy(()->{
            target.maliciousCounterValueDetected(authenticationObject).toCompletableFuture().get();
        }).getRootCause().isInstanceOf(MaliciousCounterValueException.class);
    }
}
