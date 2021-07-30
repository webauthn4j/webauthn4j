package com.webauthn4j.data.payment;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.server.ServerProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;

public class PaymentAuthenticationParameters extends AuthenticationParameters {

    public PaymentAuthenticationParameters(@NonNull PaymentServerProperty serverProperty,
                                           @NonNull Authenticator authenticator,
                                           @Nullable List<byte[]> allowCredentials,
                                           boolean userVerificationRequired,
                                           boolean userPresenceRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired, userPresenceRequired);
    }

    public PaymentAuthenticationParameters(@NonNull PaymentServerProperty serverProperty,
                                           @NonNull Authenticator authenticator,
                                           @Nullable List<byte[]> allowCredentials,
                                           boolean userVerificationRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired);
    }

}
