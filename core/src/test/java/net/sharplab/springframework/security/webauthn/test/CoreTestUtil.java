/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.*;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.client.Origin;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.client.challenge.DefaultChallenge;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.util.jackson.WebAuthnModule;
import org.springframework.util.Base64Utils;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.UUID;

/**
 * A utility class for core module test
 */
public class CoreTestUtil {

    private CoreTestUtil() {
    }

    public static WebAuthnAttestationObject createWebAuthnAttestationObjectWithFIDOU2FAttestationStatement() {
        WebAuthnAttestationObject attestationObject = new WebAuthnAttestationObject();
        String format = "fido-u2f";
        attestationObject.setAuthenticatorData(createWebAuthnAuthenticatorData());
        attestationObject.setFormat(format);
        attestationObject.setAttestationStatement(createFIDOU2FAttestationStatement());
        return attestationObject;
    }

    public static WebAuthnAuthenticatorData createWebAuthnAuthenticatorData() {
        WebAuthnAuthenticatorData authenticatorData = new WebAuthnAuthenticatorData();
        authenticatorData.setFlagUP(true);
        authenticatorData.setFlagAT(true);
        authenticatorData.setFlagED(false);
        authenticatorData.setRpIdHash(new byte[32]);
        authenticatorData.setCounter(1);
        authenticatorData.setAttestationData(createWebAuthnAttestedCredentialData());
        return authenticatorData;
    }

    public static WebAuthnAttestedCredentialData createWebAuthnAttestedCredentialData() {
        WebAuthnAttestedCredentialData attestedCredentialData = new WebAuthnAttestedCredentialData();
        attestedCredentialData.setAaGuid(new byte[16]);
        attestedCredentialData.setCredentialId(new byte[32]);
        attestedCredentialData.setCredentialPublicKey(createESCredentialPublicKey());
        return attestedCredentialData;
    }

    public static ESCredentialPublicKey createESCredentialPublicKey() {
        ESCredentialPublicKey credentialPublicKey = new ESCredentialPublicKey();
        credentialPublicKey.setAlgorithm(CoseAlgorithmConst.ES256);
        credentialPublicKey.setX(new byte[32]);
        credentialPublicKey.setY(new byte[32]);
        return credentialPublicKey;
    }

    public static RSCredentialPublicKey createRSCredentialPublicKey() {
        RSCredentialPublicKey credentialPublicKey = new RSCredentialPublicKey();
        credentialPublicKey.setAlgorithm(CoseAlgorithmConst.RS256);
        credentialPublicKey.setN(new byte[32]);
        credentialPublicKey.setE(new byte[32]);
        return credentialPublicKey;
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement() {

        byte[] sig = new byte[32];

        FIDOU2FAttestationStatement attestationStatement = new FIDOU2FAttestationStatement();
        attestationStatement.setX5c(createCertPath());
        attestationStatement.setSig(sig);
        return attestationStatement;
    }

    public static CertPath createCertPath() {
        CertPath x5c;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x5c = certificateFactory.generateCertPath(Collections.singletonList(createFirefoxSWTokenAttestationCertificate()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return x5c;
    }

    public static Certificate createFirefoxSWTokenAttestationCertificate() {
        String base64Certificate = "MIIBMTCB2KADAgECAgRdWm5nMAoGCCqGSM49BAMCMCExHzAdBgNVBAMTFkZpcmVmb3ggVTJGIFNvZnQgVG9rZW4wHhcNMTcwODE5MTExMDI3WhcNMTcwODIxMTExMDI3WjAhMR8wHQYDVQQDExZGaXJlZm94IFUyRiBTb2Z0IFRva2VuMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmNdtc7TW47xJcunwo_5ZuqSeHKJDZixC3AhTy2OEnYZfLmLZn9ssfWqLmPY4E642bKRDsm6qLNfjj_z9ufejNTAKBggqhkjOPQQDAgNIADBFAiEA6SdHwFyOq1trbQA6TLxLHS11EYUYDWyA24BnsJD8TrACIEw7k4aGBMOYlT5uMXLlj4bV5jo1Svi83VOpBo5ykMvd";
        return createCertificate(base64Certificate);
    }

    public static Certificate createFeitianU2FTokenAttestationCertificate() {
        String base64Certificate = "MIIBTDCB86ADAgECAgrMFgqn4TlPa3dQMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDEZUIEZJRE8gMDEwMDAeFw0xNjA0MTUxNDUwMzJaFw0yNjA0MTUxNDUwMzJaMCcxJTAjBgNVBAMTHEZUIEZJRE8gVTJGIDExNjE2MTczMDMwNTAyMTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATG1tXh9HyGi4UJapsP3Fw8NEwRr5WEYfV5xOvP2XU4jpnJ17SEbyZTCn7rX38Ept32BPr6IaOmamqAdQvsDpNgoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIEMDAKBggqhkjOPQQDAgNIADBFAiEA3wPvLOvjpbU3VCsKBjWtb5MzcX_I2p7NN_X03kyyFoUCIAxoJPinKGUxoNR_bhx3uZHtQQpwLWuaBND9y2Omhf47";
        return createCertificate(base64Certificate);
    }

    public static Certificate createYubikeyAttestationCertificate() {
        String base64Certificate = "MIICRDCCAS6gAwIBAgIEeMDfDjALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDIwMjU5MDU5MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1uHFcg_3-DqFcRXeshY30jBdv3oedyvS4PUDTIPJvreYl_Pf1yK_YNRj4254h7Ag7GEWAxxfsSkcLlopvuj9vozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAD72q_ZKkWsL-ZSTjdyVNOBUQAJoVninLEOnq-ZdkGX_YfRRzoo67thmidGQuVCvAHpU0THu8G_ia06nuz4yt5IFpd-nYAQ0U-NK-ETDfNSoX4xcLYcOCiiyt-1EAkH9s3krIHaw4Yr6m0Mu7vwmWLoJBcQbJKk8bsi7ptVvM-jWU9fPa9UBVFWiZZdA99zFHMAxYJzQPqbN6Tmeygh2MpB2P7TI0A9WkGmhJUkAauuwaiGiFOSZmDe0KegdflbTOlSS3ToWHIKTlUCBqn7vdJw6Vj2919ujlcxHPkRpbUGRhcJDesg6wGTBy-RyJ_96G3fH1eoMNn1F9jC9mY1Zsm4=";
        return createCertificate(base64Certificate);
    }

    public static Certificate createCertificate(String base64Certificate) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return certificateFactory.generateCertificate(new ByteArrayInputStream(Base64Utils.decodeFromUrlSafeString(base64Certificate)));
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    public static ObjectMapper createJsonMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new WebAuthnModule());
        return objectMapper;
    }

    public static ObjectMapper createCBORMapper() {
        ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
        return objectMapper;
    }

    public static CollectedClientData createClientData() {
        CollectedClientData collectedClientData = new CollectedClientData();
        collectedClientData.setChallenge(createChallenge());
        collectedClientData.setOrigin(createOrigin());
        collectedClientData.setHashAlgorithm("SHA-256");
        collectedClientData.setTokenBinding(null);
        collectedClientData.setClientExtensions(null);
        collectedClientData.setAuthenticatorExtensions(null);
        return collectedClientData;
    }

    public static Challenge createChallenge() {
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        byte[] challengeValue = ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
        return new DefaultChallenge(challengeValue);
    }

    public static Origin createOrigin() {
        return new Origin("https://localhost:8080");
    }

    public static RelyingParty createRelyingParty() {
        return new RelyingParty(createOrigin(), "localhost", createChallenge());
    }
}
