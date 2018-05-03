package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.test.TestData;
import com.webauthn4j.test.platform.AuthenticationEmulationOption;
import com.webauthn4j.test.platform.RegistrationEmulationOption;
import com.webauthn4j.util.exception.NotImplementedException;

import java.security.PrivateKey;
import java.security.cert.CertPath;

public class WebAuthnModelAuthenticator {

    private PrivateKey attestationPrivateKey;
    private CertPath attestationCertPath;
    private int counter;

    public WebAuthnModelAuthenticator(PrivateKey attestationPrivateKey, CertPath attestationCertPath, int counter){
        this.attestationPrivateKey = attestationPrivateKey;
        this.attestationCertPath = attestationCertPath;
        this.counter = counter;
    }

    public WebAuthnModelAuthenticator(){
        this(
                TestData.USER_VERIFYING_AUTHENTICATOR_PRIVATE_KEY,
                TestData.USER_VERIFYING_AUTHENTICATOR_ATTESTATION_CERT_PATH,
                0
        );
    }

    public MakeCredentialResponse makeCredential(MakeCredentialRequest makeCredentialRequest, RegistrationEmulationOption registrationEmulationOption){
        throw new NotImplementedException();
    }

    public MakeCredentialResponse makeCredential(MakeCredentialRequest makeCredentialRequest){
        return makeCredential(makeCredentialRequest, new RegistrationEmulationOption());
    }

    public GetAssertionResponse getAssertion(GetAssertionRequest getAssertionRequest, AuthenticationEmulationOption authenticationEmulationOption){
        throw new NotImplementedException();
    }

    public GetAssertionResponse getAssertion(GetAssertionRequest getAssertionRequest){
        return getAssertion(getAssertionRequest, new AuthenticationEmulationOption());
    }

}
