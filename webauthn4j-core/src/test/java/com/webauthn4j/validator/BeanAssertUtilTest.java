package com.webauthn4j.validator;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.Test;

import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;

public class BeanAssertUtilTest {

    @Test
    public void validate_WebAuthnAuthenticationContext_test(){
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                new byte[512],
                new byte[32],
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnAuthenticationContext_with_null_test(){
        BeanAssertUtil.validate((WebAuthnAuthenticationContext) null);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnAuthenticationContext_with_credentialId_null_test(){
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                null,
                new byte[512],
                new byte[512],
                new byte[32],
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnAuthenticationContext_with_clientDataJSON_null_test(){
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                null,
                new byte[512],
                new byte[32],
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnAuthenticationContext_with_authenticatorData_null_test(){
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                null,
                new byte[32],
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnAuthenticationContext_with_signature_null_test(){
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                new byte[512],
                null,
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnAuthenticationContext_with_serverProperty_null_test(){
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                new byte[512],
                new byte[32],
                null,
                null,
                true,
                null
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test
    public void validate_WebAuthnRegistrationContext_test(){
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                new byte[512],
                new byte[512],
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(registrationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnRegistrationContext_with_null_test(){
        BeanAssertUtil.validate((WebAuthnRegistrationContext)null);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnRegistrationContext_with_clientDataJSON_null_test(){
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                null,
                new byte[512],
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(registrationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnRegistrationContext_with_attestationObject_null_test(){
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                new byte[512],
                null,
                null,
                mock(ServerProperty.class),
                true,
                null
        );
        BeanAssertUtil.validate(registrationContext);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_WebAuthnRegistrationContext_with_serverProperty_null_test(){
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                new byte[512],
                new byte[512],
                null,
                null,
                true,
                null
        );
        BeanAssertUtil.validate(registrationContext);
    }


}
