package integration.scenario;

import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.anchor.TrustAnchorProvider;
import com.webauthn4j.anchor.WebAuthnTrustAnchorService;
import com.webauthn4j.anchor.WebAuthnTrustAnchorServiceImpl;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.authenticator.model.WebAuthnModelAuthenticatorAdaptor;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.fido.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.TrustAnchorCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.DefaultECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

public class UserVerifyingAuthenticatorRegistrationValidationTest {

    private Origin origin = new Origin("http://localhost");
    private WebAuthnModelAuthenticatorAdaptor webAuthnModelAuthenticatorAdaptor = new WebAuthnModelAuthenticatorAdaptor();
    private ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnModelAuthenticatorAdaptor);
    private NoneAttestationStatementValidator noneAttestationStatementValidator = new NoneAttestationStatementValidator();
    private PackedAttestationStatementValidator packedAttestationStatementValidator = new PackedAttestationStatementValidator();
    private FIDOU2FAttestationStatementValidator fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementValidator();
    private TrustAnchorProvider trustAnchorProvider = TestUtil.createTrustAnchorProviderWith3tierTestRootCACertificate();
    private WebAuthnTrustAnchorService webAuthnTrustAnchorService = new WebAuthnTrustAnchorServiceImpl(trustAnchorProvider);
    private WebAuthnRegistrationContextValidator target = new WebAuthnRegistrationContextValidator(
            Arrays.asList(noneAttestationStatementValidator, packedAttestationStatementValidator, fidoU2FAttestationStatementValidator),
            new TrustAnchorCertPathTrustworthinessValidator(webAuthnTrustAnchorService),
            new DefaultECDAATrustworthinessValidator(),
            new DefaultSelfAttestationTrustworthinessValidator()
    );

    @Test
    public void validate_WebAuthnRegistrationContext_with_none_attestation_statement_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();
        authenticatorSelectionCriteria.setAuthenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM);
        authenticatorSelectionCriteria.setRequireResidentKey(true);
        authenticatorSelectionCriteria.setUserVerificationRequirement(UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PublicKey);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PublicKey);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.NONE);
        credentialCreationOptions.setAuthenticatorSelection(authenticatorSelectionCriteria);
        credentialCreationOptions.setPubKeyCredParams(Collections.singletonList(publicKeyCredentialParameters));
        credentialCreationOptions.setUser(publicKeyCredentialUserEntity);

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), serverProperty);
        target.validate(registrationContext);
    }

    @Test
    public void validate_WebAuthnRegistrationContext_with_packed_attestation_statement_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();
        authenticatorSelectionCriteria.setAuthenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM);
        authenticatorSelectionCriteria.setRequireResidentKey(true);
        authenticatorSelectionCriteria.setUserVerificationRequirement(UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PublicKey);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();
        publicKeyCredentialParameters.setAlg(COSEAlgorithmIdentifier.ES256);
        publicKeyCredentialParameters.setType(PublicKeyCredentialType.PublicKey);

        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions();
        credentialCreationOptions.setRp(new PublicKeyCredentialRpEntity(rpId, "example.com"));
        credentialCreationOptions.setChallenge(challenge);
        credentialCreationOptions.setAttestation(AttestationConveyancePreference.DIRECT);
        credentialCreationOptions.setAuthenticatorSelection(authenticatorSelectionCriteria);
        credentialCreationOptions.setPubKeyCredParams(Collections.singletonList(publicKeyCredentialParameters));
        credentialCreationOptions.setUser(publicKeyCredentialUserEntity);

        AuthenticatorAttestationResponse registrationRequest = clientPlatform.create(credentialCreationOptions).getAuthenticatorResponse();
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, null);
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(registrationRequest.getClientDataJSON(), registrationRequest.getAttestationObject(), serverProperty);
        target.validate(registrationContext);
    }
}
