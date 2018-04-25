package com.webauthn4j.context.validator;

import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.context.RelyingParty;
import com.webauthn4j.context.WebAuthnRegistrationContext;
import com.webauthn4j.context.validator.attestation.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.context.validator.attestation.NoneAttestationStatementValidator;
import com.webauthn4j.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidatorImpl;
import com.webauthn4j.test.platform.*;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class WebAuthnRegistrationContextValidatorTest {

    private Origin origin = new Origin("http://localhost");
    private ClientPlatform clientPlatform;
    private NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator(new SelfAttestationTrustworthinessValidatorImpl());
    private WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(Arrays.asList(noneAttestationStatementValidator, fidoU2FAttestationStatementValidator));

    @Before
    public void setup(){
        clientPlatform = new ClientPlatform(origin);
    }

    @Test
    public void validate_test(){
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

}
