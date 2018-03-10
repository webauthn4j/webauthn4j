package net.sharplab.springframework.security.webauthn.util.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;
import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.util.jackson.deserializer.*;
import net.sharplab.springframework.security.webauthn.util.jackson.serializer.CertPathSerializer;
import net.sharplab.springframework.security.webauthn.util.jackson.serializer.WebAuthnAuthenticatorDataSerializer;
import net.sharplab.springframework.security.webauthn.util.jackson.serializer.X509CertificateSerializer;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

/**
 * Jackson Module for WebAuthn classes serialization and deserialization
 */
public class WebAuthnModule extends SimpleModule {

    /**
     * Default constructor
     */
    public WebAuthnModule(){
        super("WebAuthnModule");

        this.addDeserializer(CertPath.class, new CertPathDeserializer());
        this.addDeserializer(Challenge.class, new ChallengeDeserializer());
        this.addDeserializer(WebAuthnAttestationObject.class, new WebAuthnAttestationObjectDeserializer());
        this.addDeserializer(WebAuthnAuthenticatorData.class, new WebAuthnAuthenticatorDataDeserializer());
        this.addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        this.addSerializer(CertPath.class, new CertPathSerializer());
        this.addSerializer(WebAuthnAuthenticatorData.class, new WebAuthnAuthenticatorDataSerializer());
        this.addSerializer(X509Certificate.class, new X509CertificateSerializer());

        //metadata
        this.addDeserializer(LocalDate.class, new LocalDateDeserializer());
    }

}
