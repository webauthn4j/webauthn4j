package com.webauthn4j.validator;

import com.webauthn4j.attestation.WebAuthnAttestationObject;
import com.webauthn4j.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.assertion.signature.AssertionSignatureValidatorImpl;
import com.webauthn4j.converter.WebAuthnAttestationObjectConverter;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.platform.*;
import org.junit.Test;

import java.util.Arrays;

public class WebAuthnAuthenticationContextValidatorTest {

    private Origin origin = new Origin("http://localhost");
    private ClientPlatform clientPlatform = new ClientPlatform(origin);
    private AssertionSignatureValidatorImpl assertionSignatureValidator = new AssertionSignatureValidatorImpl();
    private WebAuthnAuthenticationContextValidator target = new WebAuthnAuthenticationContextValidator(assertionSignatureValidator);

    @Test
    public void validate_test() {
        String rpId = "localhost";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();

        // create
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        WebAuthnAttestationObjectConverter webAuthnAttestationObjectConverter = new WebAuthnAttestationObjectConverter();
        WebAuthnAttestationObject attestationObject = webAuthnAttestationObjectConverter.convert(registrationRequest.getAttestationObject());

        // get
        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                Arrays.asList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PublicKey,
                                attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                                Arrays.asList(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                        )
                ),
                UserVerificationRequirement.DISCOURAGED,
                null
        );
        WebAuthnAuthenticationRequest authenticationRequest = clientPlatform.get(credentialRequestOptions);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);

        WebAuthnAuthenticationContext authenticationContext =
                new WebAuthnAuthenticationContext(
                        authenticationRequest.getCredentialId(),
                        authenticationRequest.getCollectedClientData(),
                        authenticationRequest.getAuthenticatorData(),
                        authenticationRequest.getSignature(),
                        relyingParty
                );
        WebAuthnAuthenticator authenticator = TestUtil.createAuthenticator(attestationObject);
        target.validate(authenticationContext, authenticator, false);
    }

}
