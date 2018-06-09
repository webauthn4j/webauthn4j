package com.webauthn4j.validator;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.client.*;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.Test;

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

    @Test
    public void validate_clientData_test(){
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                new DefaultChallenge(),
                new Origin("https://example.com"),
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_clientData_with_null_test(){

        BeanAssertUtil.validate((CollectedClientData) null);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_clientData_with_clientDataType_null_test(){
        CollectedClientData collectedClientData = new CollectedClientData(
                null,
                new DefaultChallenge(),
                new Origin("https://example.com"),
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_clientData_with_challenge_null_test(){
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                null,
                new Origin("https://example.com"),
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_clientData_with_origin_null_test(){
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                new DefaultChallenge(),
                null,
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test
    public void validate_clientData_with_tokenBinding_null_test(){
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                new DefaultChallenge(),
                new Origin("https://example.com"),
                null
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test
    public void validate_tokenBinding_test(){
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, new byte[32]);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test
    public void validate_tokenBinding_with_not_supported_status_test(){
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.NOT_SUPPORTED, (String)null);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test
    public void validate_tokenBinding_with_supported_status_test(){
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.SUPPORTED, (String)null);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_tokenBinding_with_status_null_test(){
        TokenBinding tokenBinding = new TokenBinding(null, (String)null);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test
    public void validate_attestationObject_test(){
        AttestationObject attestationObject = new AttestationObject(TestUtil.createAuthenticatorData(), TestUtil.createFIDOU2FAttestationStatement());

        BeanAssertUtil.validate(attestationObject);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_attestationObject_with_null_test(){

        BeanAssertUtil.validate((AttestationObject) null);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_attestationObject_with_authenticatorData_null_test(){
        AttestationObject attestationObject = new AttestationObject(null, TestUtil.createFIDOU2FAttestationStatement());

        BeanAssertUtil.validate(attestationObject);
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_attestationObject_with_attestationStatement_null_test(){
        AttestationObject attestationObject = new AttestationObject(TestUtil.createAuthenticatorData(), null);

        BeanAssertUtil.validate(attestationObject);
    }




}
