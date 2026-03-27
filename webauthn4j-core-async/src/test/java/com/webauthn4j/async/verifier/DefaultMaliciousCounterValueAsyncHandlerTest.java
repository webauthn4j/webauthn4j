package com.webauthn4j.async.verifier;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultMaliciousCounterValueAsyncHandlerTest {

    @Test
    void test() {
        DefaultMaliciousCounterValueAsyncHandler target = new DefaultMaliciousCounterValueAsyncHandler();
        AuthenticationObject authenticationObject = mock(AuthenticationObject.class);
        Authenticator authenticator = mock(Authenticator.class);
        AuthenticatorData authenticatorData = mock(AuthenticatorData.class);

        when(authenticationObject.getAuthenticator()).thenReturn(authenticator);
        when(authenticationObject.getAuthenticatorData()).thenReturn(authenticatorData);
        when(authenticator.getCounter()).thenReturn(100L);
        when(authenticatorData.getSignCount()).thenReturn(50L);

        assertThatThrownBy(()->{
            target.maliciousCounterValueDetected(authenticationObject).toCompletableFuture().get();
        }).getRootCause().isInstanceOf(MaliciousCounterValueException.class);
    }
}
