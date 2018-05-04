package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.authenticator.ESCredentialPublicKey;
import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestData;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.util.KeyUtil;
import com.webauthn4j.util.WIP;
import com.webauthn4j.util.exception.NotImplementedException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.util.*;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.*;

@WIP
public class WebAuthnModelAuthenticator {

    private PrivateKey attestationPrivateKey;
    private CertPath attestationCertPath;
    private boolean capableOfUserVerification;
    byte[] aaGuid;
    private int counter;
    private Map<CredentialMapKey, PublicKeyCredentialSource> credentialMap;

    public WebAuthnModelAuthenticator(PrivateKey attestationPrivateKey, CertPath attestationCertPath, boolean capableOfUserVerification, byte[] aaGuid, int counter){
        this.attestationPrivateKey = attestationPrivateKey;
        this.attestationCertPath = attestationCertPath;
        this.capableOfUserVerification = capableOfUserVerification;
        this.aaGuid = aaGuid;
        this.counter = counter;
        this.credentialMap = new HashMap<>();
    }

    public WebAuthnModelAuthenticator(){
        this(
                TestData.USER_VERIFYING_AUTHENTICATOR_PRIVATE_KEY,
                TestData.USER_VERIFYING_AUTHENTICATOR_ATTESTATION_CERT_PATH,
                true,
                new byte[16],
                0
        );
    }

    public PublicKeyCredentialSource lookup(byte[] credentialId){

        if(!isCapableOfStoringClientSideResidentCredential()){
            PublicKeyCredentialSource credentialSource = null; //TODO: decrypt credentialId into a credSource;
            return credentialSource;
        }
        for(Map.Entry<CredentialMapKey, PublicKeyCredentialSource> entry : credentialMap.entrySet()){
            if(Arrays.equals(credentialId, entry.getValue().getId())){
                return entry.getValue();
            }
        }
        return null;
    }

    public MakeCredentialResponse makeCredential(MakeCredentialRequest makeCredentialRequest, RegistrationEmulationOption registrationEmulationOption){

        PublicKeyCredentialRpEntity rpEntity = makeCredentialRequest.getRpEntity();

        // Check if all the supplied parameters are syntactically well-formed and of the correct length.
        // If not, return an error code equivalent to "UnknownError" and terminate the operation.
        //TODO

        // Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters
        // in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError"
        // and terminate the operation.
        Optional<PublicKeyCredentialParameters> optionalPublicKeyCredentialParameters =
                makeCredentialRequest.getCredTypesAndPublicKeyAlgs().stream().filter(this::isCapableOfHandling).findFirst();
        PublicKeyCredentialParameters publicKeyCredentialParameters;
        if(optionalPublicKeyCredentialParameters.isPresent()) {
            publicKeyCredentialParameters = optionalPublicKeyCredentialParameters.get();
        } else {
            throw new NotSupportedException("Specified PublicKeyCredentialParameters are not supported");
        }

        // For each descriptor of excludeCredentialDescriptorList:
        for (PublicKeyCredentialDescriptor descriptor : makeCredentialRequest.getExcludeCredentialDescriptorList()){
            PublicKeyCredentialSource publicKeyCredentialSource = lookup(descriptor.getId());
            if(publicKeyCredentialSource != null){
                if(publicKeyCredentialSource.getRpId().equals(rpEntity.getId()) &&
                        publicKeyCredentialSource.getType().equals(descriptor.getType())){
                    boolean userConsent = true;
                    if(userConsent){
                        throw new InvalidStateException("");
                    }
                    else {
                        throw new NotAllowedException("User consent is required");
                    }
                }
            }
        }
        if(makeCredentialRequest.isRequireResidentKey() && isCapableOfStoringClientSideResidentCredential()){
            throw new ConstraintException("Authenticator isn't capable of storing client-side resident credential");
        }
        if(makeCredentialRequest.isRequireUserVerification() && isCapableOfUserVerification()){
            throw new ConstraintException("Authenticator isn't capable of user verification");
        }

        boolean userVerification = true;
        boolean userConsent = true;
        if(makeCredentialRequest.isRequireUserVerification() && !userVerification){
            throw new NotAllowedException("User is not verified.");
        }
        if(makeCredentialRequest.isRequireUserPresence() && !userConsent){
            throw new NotAllowedException("User doesn't provide consent.");
        }

        byte[] credentialId;
        PrivateKey credentialPrivateKey;
        CredentialPublicKey credentialPublicKey;
        try{
            KeyPair keyPair = KeyUtil.createKeyPair();
            credentialPrivateKey = keyPair.getPrivate();
            credentialPublicKey = ESCredentialPublicKey.create(keyPair.getPublic());

            byte[] userHandle = makeCredentialRequest.getUserEntity().getId();
            PublicKeyCredentialSource credentialSource = new PublicKeyCredentialSource();
            credentialSource.setType(PublicKeyCredentialType.PublicKey);
            credentialSource.setPrivateKey(credentialPrivateKey);
            credentialSource.setRpId(rpEntity.getId());
            credentialSource.setUserHandle(userHandle);
            credentialSource.setOtherUI(null);

            if(makeCredentialRequest.isRequireResidentKey()){
                credentialId = new byte[32];
                new SecureRandom().nextBytes(credentialId);
                credentialSource.setId(credentialId);
                credentialMap.put(new CredentialMapKey(rpEntity.getId(), userHandle), credentialSource);
            }
            else {
                // TODO: Let credentialId be the result of serializing and encrypting credentialSource so that only this authenticator can decrypt it.
                credentialId = null;
            }
        }
        catch (RuntimeException e){
            throw new WebAuthnModelException(e);
        }

        //TODO: extension processing
        List<Extension> processedExtensions = Collections.EMPTY_LIST;

        // TODO: counter mode

        byte[] rpIdHash = null; //TODO
        byte flag = BIT_AT;
        if(userConsent) flag |= BIT_UP;
        if(userVerification) flag |= BIT_UV;
        if(processedExtensions.size()>0) flag |= BIT_ED;

        AttestedCredentialData attestedCredentialData = new AttestedCredentialData(aaGuid, credentialId, credentialPublicKey);
        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setRpIdHash(rpIdHash);
        authenticatorData.setFlags(flag);
        authenticatorData.setCounter(counter);
        authenticatorData.setAttestedCredentialData(attestedCredentialData);
        authenticatorData.setExtensions(processedExtensions);

        AttestationStatement attestationStatement = new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, null, attestationCertPath, null);

        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);
        MakeCredentialResponse makeCredentialResponse = new MakeCredentialResponse();
        makeCredentialResponse.setAttestationObject(attestationObject);
        return makeCredentialResponse;
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

    public boolean isCapableOfUserVerification(){
        return capableOfUserVerification;
    }

    public boolean isCapableOfStoringClientSideResidentCredential() {
        return true;
    }

    private boolean isCapableOfHandling(PublicKeyCredentialParameters publicKeyCredentialParameters) {
        return true; //TODO
    }


}
