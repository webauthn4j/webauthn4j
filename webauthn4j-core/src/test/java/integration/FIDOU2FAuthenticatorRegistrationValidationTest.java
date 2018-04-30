package integration;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.basic.BasicTrustworthinessValidator;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.validator.exception.*;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_GET;
import static org.mockito.Mockito.mock;

public class FIDOU2FAuthenticatorRegistrationValidationTest {

    private Origin origin = new Origin("http://localhost");
    private ClientPlatform clientPlatform = new ClientPlatform(origin);
    private NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator(mock(BasicTrustworthinessValidator.class));
    private WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(Arrays.asList(noneAttestationStatementValidator, fidoU2FAttestationStatementValidator));

    @Test
    public void validate_test() {
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

    @Test
    public void validate_with_direct_attestation_conveyance_preference_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.DIRECT);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = MaliciousDataException.class)
    public void validate_with_bad_clientData_type_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        CollectedClientData collectedClientData = clientPlatform.createCollectedClientData(TYPE_WEBAUTHN_GET, challenge);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions, collectedClientData);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadChallengeException.class)
    public void validate_with_bad_challenge_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        Challenge badChallenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(badChallenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadOriginException.class)
    public void validate_with_bad_origin_test() {
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        Origin badOrigin = new Origin("http://bad.origin.example.com");
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        ClientPlatform clientPlatform = new ClientPlatform(badOrigin);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);

        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadRpIdException.class)
    public void validate_with_bad_rpId_test() {
        String rpId = "localhost";
        String badRpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(badRpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        target.validate(registrationContext);
    }

    @Test(expected = BadAttestationStatementException.class)
    public void validate_with_bad_attestationStatement_test(){
        String rpId = "localhost";
        Challenge challenge = new DefaultChallenge();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "localhost"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);

        WebAuthnRegistrationRequest registrationRequest = clientPlatform.create(credentialCreationOptions);
        RelyingParty relyingParty = new RelyingParty(origin, rpId, challenge);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getCollectedClientData(), registrationRequest.getAttestationObject(), relyingParty);
        WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(Collections.singletonList(fidoU2FAttestationStatementValidator));
        target.validate(registrationContext);
    }

}
