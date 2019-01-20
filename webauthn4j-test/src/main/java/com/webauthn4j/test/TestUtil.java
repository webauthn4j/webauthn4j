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

package com.webauthn4j.test;

import com.webauthn4j.anchor.TrustAnchorResolver;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.attestation.authenticator.*;
import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.client.Origin;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.response.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.authenticator.model.WebAuthnModelException;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.KeyUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.function.Function;

import static com.webauthn4j.response.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.response.attestation.authenticator.AuthenticatorData.BIT_UP;

/**
 * A utility class for core module test
 */
public class TestUtil {

    private static Registry registry = new Registry();
    private static CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(registry);
    private static AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(registry);
    private static AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(registry);

    private TestUtil() {
    }

    public static RegistrationObject createRegistrationObject(Function<byte[], AttestationObject> attestationObjectProvider) {
        CollectedClientData collectedClientData = createClientData(ClientDataType.CREATE);
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        AttestationObject attestationObject = attestationObjectProvider.apply(collectedClientDataBytes);
        byte[] attestationObjectBytes =attestationObjectConverter.convertToBytes(attestationObject);
        AuthenticatorData authenticatorData = TestUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
        return new RegistrationObject(
                collectedClientData,
                collectedClientDataBytes,
                attestationObject,
                attestationObjectBytes,
                authenticatorDataBytes,
                TestUtil.createServerProperty()
        );
    }

    public static RegistrationObject createRegistrationObjectWithTPMAttestation(){
        byte[] collectedClientDataBytes = Base64UrlUtil.decode("ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIndrNkxxRVhBTUFacHFjVFlsWTJ5b3I1RGppeUlfYjFneTluRE90Q0IxeUdZbm1fNFdHNFVrMjRGQXI3QXhUT0ZmUU1laWdrUnhPVExaTnJMeEN2Vl9RIiwNCgkib3JpZ2luIiA6ICJodHRwczovL3dlYmF1dGhuLm9yZyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9");
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(collectedClientDataBytes);
        byte[] attestationObjectBytes = Base64UrlUtil.decode("o2NmbXRjdHBtaGF1dGhEYXRhWQFnlWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIIVs3RYj2zjEOSjQbDIbPmXofBdIkx6x-t2CpK8SRYI0pAEDAzkBACBZAQDF2m9Nk1e94gL1xVjNCjFW0lTy4K2atXkx-YJrdH3hrE8p1gcIdNzleRDhmERJnY5CRwM5sXDQIrUBq4jpwvTtMC5HGccN6-iEJAPtm9_CJzCmGhtw9hbF8bcAys94RhN9xLLUaajhWqtPrYZXCEAi0o9E2QdTIxJrcAfJgZOf33JMr0--R1BAQxpOoGRDC8ss-tfQW9ufZLWw4JUuz4Z5Jz1sbfqBYB8UUDMWoT0HgsMaPmvd7T17xGvB-pvvDf-Dt96vFGtYLEZEgho8Yu26pr5CK_BOQ-2vX9N4MIYVPXNhogMGGmKYqybhM3yhye0GdBpZBUd5iOcgME6uGJ1_IUMBAAFnYXR0U3RtdKZjdmVyYzIuMGNhbGc5__5jc2lnWQEAcV1izWGUWIs0DEOZNQGdriNNXo6nbrGDLzEAeswCK9njYGCLmOkHVgSyafhsjCEMZkQmuPUmEOMDKosqxup_tiXQwG4yCW9TyWoINWGayQ4vcr6Ys-l6KMPkg__d2VywhfonnTJDBfE_4BIRD60GR0qBzTarthDHQFMqRtoUtuOsTF5jedU3EQPojRA5iCNC2naCCZuMSURdlPmhlW5rAaRZVF41ZZECi5iFOM2rO0UpGuQSLUvr1MqQOsDytMf7qWZMvwT_5_8BF6GNdB2l2VzmIJBbV6g8z7dj0fRkjlCXBp8UG2LvTq5SsfugrRWXOJ8BkdMplPfl0mz6ssU_n2N4NWOCWQS2MIIEsjCCA5qgAwIBAgIQEyidpWZzRxOSMNfrAvV1fzANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELTE1OTFENEI2RUFGOThEMDEwNDg2NEI2OTAzQTQ4REQwMDI2MDc3RDMwHhcNMTgwNTIwMTYyMDQ0WhcNMjgwNTIwMTYyMDQ0WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ6XK2ujM11E7x4SL34p252ncyQTd3-4r5ALQhBbFKS95gUsuENTG-48GBQwu48i06cckm3eH20TUeJvn4-pj6i8LFOrIK14T3P3GFzbxgQLq1KVm63JWDdEXk789JgzQjHNO7DZFKWTEiktwmBUPUA88TjQcXOtrR5EXTrt1FzGzabOepFann3Ny_XtxI8lDZ3QLwPLJfmk7puGtkGNaXOsRC7GLAnoEB7UWvjiyKG6HAtvVTgxcW5OQnHFb9AHycU5QdukXrP0njdCpLCRR0Nq6VMKmVU3MaGh-DCwYEB32sPNPdDkPDWyk16ItwcmXqfSBV5ZOr8ifvcXbCWUWwIDAQABo4IB5TCCAeEwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwbQYDVR0gAQH_BGMwYTBfBgkrBgEEAYI3FR8wUjBQBggrBgEFBQcCAjBEHkIAVABDAFAAQQAgACAAVAByAHUAcwB0AGUAZAAgACAAUABsAGEAdABmAG8AcgBtACAAIABJAGQAZQBuAHQAaQB0AHkwEAYDVR0lBAkwBwYFZ4EFCAMwSgYDVR0RAQH_BEAwPqQ8MDoxODAOBgVngQUCAwwFaWQ6MTMwEAYFZ4EFAgIMB05QQ1Q2eHgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMB8GA1UdIwQYMBaAFMISqVvO-lb4wMFvsVvdAzRHs3qjMB0GA1UdDgQWBBSv4kXTSA8i3NUM0q57lrWpM8p_4TCBswYIKwYBBQUHAQEEgaYwgaMwgaAGCCsGAQUFBzAChoGTaHR0cHM6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1udGMta2V5aWQtMTU5MWQ0YjZlYWY5OGQwMTA0ODY0YjY5MDNhNDhkZDAwMjYwNzdkMy8zYjkxOGFlNC0wN2UxLTQwNTktOTQ5MS0wYWQyNDgxOTA4MTguY2VyMA0GCSqGSIb3DQEBCwUAA4IBAQAs-vqdkDX09fNNYqzbv3Lh0vl6RgGpPGl-MYgO8Lg1I9UKvEUaaUHm845ABS8m7r9p22RCWO6TSEPS0YUYzAsNuiKiGVna4nB9JWZaV9GDS6aMD0nJ8kNciorDsV60j0Yb592kv1VkOKlbTF7-Z10jaapx0CqhxEIUzEBb8y9Pa8oOaQf8ORhDHZp-mbn_W8rUzXSDS0rFbWKaW4tGpVoKGRH-f9vIeXxGlxVS0wqqRm_r-h1aZInta0OOiL_S4367gZyeLL3eUnzdd-eYySYn2XINPbVacK8ZifdsLMwiNtz5uM1jbqpEn2UoB3Hcdn0hc12jTLPWFfg7GiKQ0hk9WQXsMIIF6DCCA9CgAwIBAgITMwAAAQDiBsSROVGXhwAAAAABADANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMtTWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4XDTE3MDIwMTE3NDAyNFoXDTI5MTIzMTE3NDAyNFowQTE_MD0GA1UEAxM2TkNVLU5UQy1LRVlJRC0xNTkxRDRCNkVBRjk4RDAxMDQ4NjRCNjkwM0E0OEREMDAyNjA3N0QzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9IwUMSiQUbrQR0NLkKR-9RB8zfHYdlmDB0XN_m8qrNHKRJ__lBOR-mwU_h3MFRZF6X3ZZwka1DtwBdzLFV8lVu33bc15stjSd6B22HRRKQ3sIns5AYQxg0eX2PtWCJuIhxdM_jDjP2hq9Yvx-ibt1IO9UZwj83NGxXc7Gk2UvCs9lcFSp6U8zzl5fGFCKYcxIKH0qbPrzjlyVyZTKwGGSTeoMMEdsZiq-m_xIcrehYuHg-FAVaPLLTblS1h5cu80-ruFUm5Xzl61YjVU9tAV_Y4joAsJ5QP3VPocFhr5YVsBVYBiBcQtr5JFdJXZWWEgYcFLdAFUk8nJERS7-5xLuQIDAQABo4IBizCCAYcwCwYDVR0PBAQDAgGGMBsGA1UdJQQUMBIGCSsGAQQBgjcVJAYFZ4EFCAMwFgYDVR0gBA8wDTALBgkrBgEEAYI3FR8wEgYDVR0TAQH_BAgwBgEB_wIBADAdBgNVHQ4EFgQUwhKpW876VvjAwW-xW90DNEezeqMwHwYDVR0jBBgwFoAUeowKzi9IYhfilNGuVcFS7HF0pFYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMTQuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQAKc9z1UUBAaybIVnK8yL1N1iGJFFFFw_PpkxW76hgQhUcCxNFQskfahfFzkBD05odVC1DKyk2PyOle0G86FCmZiJa14MtKNsiu66nVqk2hr8iIcu-cYEsgb446yIGd1NblQKA1C_28F2KHm8YRgcFtRSkWEMuDiVMa0HDU8aI6ZHO04Naj86nXeULJSZsA0pQwNJ04-QJP3MFQzxQ7md6D-pCx-LVA-WUdGxT1ofaO5NFxq0XjubnZwRjQazy_m93dKWp19tbBzTUKImgUKLYGcdmVWXAxUrkxHN2FbZGOYWfmE2TGQXS2Z-g4YAQo1PleyOav3HNB8ti7u5HpI3t9a73xuECy2gFcZQ24DJuBaQe4mU5I_hPiAa-822nPPL6w8m1eegxhHf7ziRW_hW8s1cvAZZ5Jpev96zL_zRv34MsRWhKwLbu2oOCSEYYh8D8DbQZjmsxlUYR_q1cP8JKiIo6NNJ85g7sjTZgXxeanA9wZwqwJB-P98VdVslC17PmVu0RHOqRtxrht7OFT7Z10ecz0tj9ODXrv5nmBktmbgHRirRMl84wp7-PJhTXdHbxZv-OoL4HP6FxyDbHxLB7QmR4-VoEZN0vsybb1A8KEj2pkNY_tmxHH6k87euM99bB8FHrW9FNrXCGL1p6-PYtiky52a5YQZGT8Hz-ZnxobTmhjZXJ0SW5mb1ih_1RDR4AXACIAC7xZ9N_ZpqQtw7hmr_LfDRmCa78BS2erCtbrsXYwa4AHABSsnz8FacZi-wkUkfHu4xjG8MPfmwAAAAGxWkjHaED549jznwUBqeDEpT-7xBMAIgALcSGuv6a5r9BwMvQvCSXg7GdAjdWZpXv6D4DH8VYBCE8AIgALAVI0eQ_AAZjNvrhUEMK2q4wxuwIFOnHIDF0Qljhf47RncHViQXJlYVkBNgABAAsABgRyACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAIAAAAAAABAMXab02TV73iAvXFWM0KMVbSVPLgrZq1eTH5gmt0feGsTynWBwh03OV5EOGYREmdjkJHAzmxcNAitQGriOnC9O0wLkcZxw3r6IQkA-2b38InMKYaG3D2FsXxtwDKz3hGE33EstRpqOFaq0-thlcIQCLSj0TZB1MjEmtwB8mBk5_fckyvT75HUEBDGk6gZEMLyyz619Bb259ktbDglS7PhnknPWxt-oFgHxRQMxahPQeCwxo-a93tPXvEa8H6m-8N_4O33q8Ua1gsRkSCGjxi7bqmvkIr8E5D7a9f03gwhhU9c2GiAwYaYpirJuEzfKHJ7QZ0GlkFR3mI5yAwTq4YnX8");
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        byte[] authenticatorDataBytes = attestationObjectConverter.extractAuthenticatorData(attestationObjectBytes);
        return new RegistrationObject(collectedClientData, collectedClientDataBytes, attestationObject, attestationObjectBytes, authenticatorDataBytes, TestUtil.createServerProperty());
    }

    public static AttestationObject createAttestationObjectWithFIDOU2FAttestationStatement() {
        return new AttestationObject(createAuthenticatorData(), createFIDOU2FAttestationStatement());
    }

    public static AttestationObject createAttestationObjectWithBasicPackedECAttestationStatement(byte[] clientDataHash) {
        PrivateKey privateKey = TestUtil.load3tierTestAuthenticatorAttestationPrivateKey();
        AuthenticatorData authenticatorData = createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(new Registry()).convert(authenticatorData);
        byte[] signedData = getSignedData(authenticatorDataBytes, clientDataHash);
        byte[] signature = calculateSignature(privateKey, signedData);
        return new AttestationObject(authenticatorData, createBasicPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature));
    }

    public static AttestationObject createAttestationObjectWithSelfPackedECAttestationStatement(byte[] clientDataHash) {
        KeyPair keyPair = KeyUtil.createECKeyPair();
        EC2CredentialPublicKey ec2CredentialPublicKey = EC2CredentialPublicKey.create((ECPublicKey) keyPair.getPublic());
        AuthenticatorData authenticatorData = createAuthenticatorData(ec2CredentialPublicKey);
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(new Registry()).convert(authenticatorData);
        byte[] signedData = getSignedData(authenticatorDataBytes, clientDataHash);
        byte[] signature = calculateSignature(keyPair.getPrivate(), signedData);
        return new AttestationObject(authenticatorData, createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature));
    }

    public static AttestationObject createAttestationObjectWithSelfPackedRSAAttestationStatement(byte[] clientDataHash) {
        KeyPair keyPair = KeyUtil.createRSAKeyPair();
        RSACredentialPublicKey rsaCredentialPublicKey = RSACredentialPublicKey.create((RSAPublicKey) keyPair.getPublic());
        AuthenticatorData authenticatorData = createAuthenticatorData(rsaCredentialPublicKey);
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(new Registry()).convert(authenticatorData);
        byte[] signedData = getSignedData(authenticatorDataBytes, clientDataHash);
        byte[] signature = calculateSignature(keyPair.getPrivate(), signedData);
        return new AttestationObject(authenticatorData, createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.RS256, signature));
    }

    public static AttestationObject createAttestationObjectWithAndroidKeyAttestationStatement(byte[] clientDataHash) {
        PrivateKey privateKey = TestUtil.loadAndroidKeyAttestationPrivateKey();
        AuthenticatorData authenticatorData = createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(new Registry()).convert(authenticatorData);
        byte[] signedData = getSignedData(authenticatorDataBytes, clientDataHash);
        byte[] signature = calculateSignature(privateKey, signedData);
        return new AttestationObject(authenticatorData, createAndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, signature));
    }


    public static AttestationObject createAttestationObjectWithTPMAttestationStatement(byte[] clientDataHash) {
        PrivateKey privateKey = TestUtil.loadTPMAttestationPrivateKey();
        AuthenticatorData authenticatorData = createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(new Registry()).convert(authenticatorData);
        byte[] signedData = getSignedData(authenticatorDataBytes, clientDataHash);
        byte[] signature = calculateSignature(privateKey, signedData);
        return new AttestationObject(authenticatorData, createTPMAttestationStatement(COSEAlgorithmIdentifier.RS1, signature));
    }

    private static PrivateKey loadAndroidKeyAttestationPrivateKey() {
        throw new NotImplementedException();
    }


    private static PrivateKey loadTPMAttestationPrivateKey() {
        throw new NotImplementedException();
    }


    private static byte[] getSignedData(byte[] authenticatorData, byte[] clientDataHash) {
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    public static AuthenticatorData createAuthenticatorData() {
        byte flags = BIT_UP | BIT_AT;
        return new AuthenticatorData(new byte[32], flags, 1, createAttestedCredentialData());
    }

    public static AuthenticatorData createAuthenticatorData(CredentialPublicKey credentialPublicKey) {
        byte flags = BIT_UP | BIT_AT;
        return new AuthenticatorData(new byte[32], flags, 1, createAttestedCredentialData(credentialPublicKey));
    }

    public static AttestedCredentialData createAttestedCredentialData() {
        return createAttestedCredentialData(createECCredentialPublicKey());
    }

    public static AttestedCredentialData createAttestedCredentialData(CredentialPublicKey credentialPublicKey) {
        return new AttestedCredentialData(AAGUID.ZERO, new byte[32], credentialPublicKey);
    }

    public static EC2CredentialPublicKey createECCredentialPublicKey() {
        return new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                new byte[32],
                new byte[32]
        );
    }

    public static RSACredentialPublicKey createRSCredentialPublicKey() {
        RSACredentialPublicKey credentialPublicKey;
        credentialPublicKey = new RSACredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.RS256,
                null,
                null,
                new byte[32],
                new byte[32]
        );
        return credentialPublicKey;
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement() {
        return createFIDOU2FAttestationStatement(create2tierTestAuthenticatorCertPath());
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement(AttestationCertificatePath certPath) {

        byte[] sig = new byte[32];

        return new FIDOU2FAttestationStatement(certPath, sig);
    }

    public static PackedAttestationStatement createBasicPackedAttestationStatement() {
        byte[] signature = new byte[32]; // dummy
        return createBasicPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature);
    }

    public static PackedAttestationStatement createBasicPackedAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        AttestationCertificatePath certPath = load3tierTestCertPath();
        return new PackedAttestationStatement(algorithm, signature, certPath, null);
    }

    public static PackedAttestationStatement createSelfPackedAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        return new PackedAttestationStatement(algorithm, signature, null, null);
    }

    public static AndroidKeyAttestationStatement createAndroidKeyAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        AttestationCertificatePath certPath = loadAndroidKeyCertPath();
        return new AndroidKeyAttestationStatement(algorithm, signature, certPath);
    }

    private static AttestationStatement createTPMAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        AttestationCertificatePath certPath = loadAndroidKeyCertPath();
        TPMSAttest certInfo = null; //TODO
        TPMTPublic pubArea = null; //TODO
        return new TPMAttestationStatement(algorithm, certPath, null, signature, certInfo, pubArea);
    }

    public static AttestationCertificatePath create2tierTestAuthenticatorCertPath() {
        return new AttestationCertificatePath(Collections.singletonList(TestUtil.load2tierTestAuthenticatorAttestationCertificate()));
    }

    public static AttestationCertificatePath load3tierTestCertPath() {
        return new AttestationCertificatePath(Arrays.asList(load3tierTestAuthenticatorAttestationCertificate(), load3tierTestIntermediateCACertificate()));
    }

    public static X509Certificate load3tierTestRootCACertificate() {
        return loadCertificateFromClassPath("/attestation/3tier/certs/3tier-test-root-CA.crt");
    }

    public static X509Certificate load3tierTestIntermediateCACertificate() {
        return loadCertificateFromClassPath("/attestation/3tier/certs/3tier-test-intermediate-CA.crt");
    }

    public static X509Certificate load3tierTestAuthenticatorAttestationCertificate() {
        return loadCertificateFromClassPath("/attestation/3tier/certs/3tier-test-authenticator.crt");
    }

    public static X509Certificate load2tierTestRootCACertificate() {
        return loadCertificateFromClassPath("/attestation/2tier/certs/2tier-test-root-CA.crt");
    }

    public static X509Certificate load2tierTestAuthenticatorAttestationCertificate() {
        return loadCertificateFromClassPath("/attestation/2tier/certs/2tier-test-authenticator.crt");
    }

    private static AttestationCertificatePath loadAndroidKeyCertPath() {
        throw new NotImplementedException();
    }

    public static X509Certificate loadCertificateFromClassPath(String classPath) {
        ClassPathResource resource = new ClassPathResource(classPath);
        try {
            return CertificateUtil.generateX509Certificate(resource.getInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509Certificate loadFirefoxSWTokenAttestationCertificate() {
        String base64UrlCertificate = "MIIBMTCB2KADAgECAgRdWm5nMAoGCCqGSM49BAMCMCExHzAdBgNVBAMTFkZpcmVmb3ggVTJGIFNvZnQgVG9rZW4wHhcNMTcwODE5MTExMDI3WhcNMTcwODIxMTExMDI3WjAhMR8wHQYDVQQDExZGaXJlZm94IFUyRiBTb2Z0IFRva2VuMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmNdtc7TW47xJcunwo_5ZuqSeHKJDZixC3AhTy2OEnYZfLmLZn9ssfWqLmPY4E642bKRDsm6qLNfjj_z9ufejNTAKBggqhkjOPQQDAgNIADBFAiEA6SdHwFyOq1trbQA6TLxLHS11EYUYDWyA24BnsJD8TrACIEw7k4aGBMOYlT5uMXLlj4bV5jo1Svi83VOpBo5ykMvd";
        return CertificateUtil.generateX509Certificate(Base64UrlUtil.decode(base64UrlCertificate));
    }

    public static X509Certificate loadFeitianU2FTokenAttestationCertificate() {
        String base64UrlCertificate = "MIIBTDCB86ADAgECAgrMFgqn4TlPa3dQMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDEZUIEZJRE8gMDEwMDAeFw0xNjA0MTUxNDUwMzJaFw0yNjA0MTUxNDUwMzJaMCcxJTAjBgNVBAMTHEZUIEZJRE8gVTJGIDExNjE2MTczMDMwNTAyMTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATG1tXh9HyGi4UJapsP3Fw8NEwRr5WEYfV5xOvP2XU4jpnJ17SEbyZTCn7rX38Ept32BPr6IaOmamqAdQvsDpNgoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIEMDAKBggqhkjOPQQDAgNIADBFAiEA3wPvLOvjpbU3VCsKBjWtb5MzcX_I2p7NN_X03kyyFoUCIAxoJPinKGUxoNR_bhx3uZHtQQpwLWuaBND9y2Omhf47";
        return CertificateUtil.generateX509Certificate(Base64UrlUtil.decode(base64UrlCertificate));
    }

    public static X509Certificate loadYubikeyAttestationCertificate() {
        String base64UrlCertificate = "MIICRDCCAS6gAwIBAgIEeMDfDjALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDIwMjU5MDU5MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1uHFcg_3-DqFcRXeshY30jBdv3oedyvS4PUDTIPJvreYl_Pf1yK_YNRj4254h7Ag7GEWAxxfsSkcLlopvuj9vozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAD72q_ZKkWsL-ZSTjdyVNOBUQAJoVninLEOnq-ZdkGX_YfRRzoo67thmidGQuVCvAHpU0THu8G_ia06nuz4yt5IFpd-nYAQ0U-NK-ETDfNSoX4xcLYcOCiiyt-1EAkH9s3krIHaw4Yr6m0Mu7vwmWLoJBcQbJKk8bsi7ptVvM-jWU9fPa9UBVFWiZZdA99zFHMAxYJzQPqbN6Tmeygh2MpB2P7TI0A9WkGmhJUkAauuwaiGiFOSZmDe0KegdflbTOlSS3ToWHIKTlUCBqn7vdJw6Vj2919ujlcxHPkRpbUGRhcJDesg6wGTBy-RyJ_96G3fH1eoMNn1F9jC9mY1Zsm4=";
        return CertificateUtil.generateX509Certificate(Base64UrlUtil.decode(base64UrlCertificate));
    }

    public static X509Certificate loadAndroidKeyAttestationCertificate() {
        String certificate =
                "-----BEGIN CERTIFICATE-----\n"
                        + "MIIByTCCAXCgAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFBbmRyb2lkIE"
                        + "tleW1hc3Rl cjAgFw03MDAxMDEwMDAwMDBaGA8yMTA2MDIwNzA2MjgxNVowGjEYMBY"
                        + "GA1UEAwwPQSBLZXltYXN0 ZXIgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
                        + "FpsFUWID9p2QPAvtfal4MRf9vJg0tNc3 vKJwoDhhSCMm7If0FljgvmroBYQyCIbnn"
                        + "Bxh2OU9SKxI/manPwIIUqOBojCBnzALBgNVHQ8EBAMC B4AwbwYKKwYBBAHWeQIBEQ"
                        + "RhMF8CAQEKAQACAQEKAQEEBWhlbGxvBAAwDL+FPQgCBgFWDy29GDA6 oQUxAwIBAqI"
                        + "DAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBA7+DeQQCAgEsv4U+AwIBAL+FPwIF "
                        + "ADAfBgNVHSMEGDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAKBggqhkjOPQQDAgNHAD"
                        + "BEAiBKzJSk 9VNauKu4dr+ZJ5jMTNlAxSI99XkKEkXSolsGSAIgCnd5T99gv3B/IqM"
                        + "CHn0yZ7Wuu/jisU0epRRo xh8otA8=\n"
                        + "-----END CERTIFICATE-----";
        return createCertificate(certificate);
    }

    public static X509Certificate loadAndroidKeyIntermidiateCertificate() {
        String certificate =
                "-----BEGIN CERTIFICATE-----\n" +
                        "MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQ"
                        + "YDVQQIDApD YWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQ"
                        + "KDAxHb29nbGUsIEluYy4x EDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJv"
                        + "aWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0 ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwM"
                        + "DQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQG EwJVUzETMBEGA1UECAwKQ2"
                        + "FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQL DAdBbmRyb2l"
                        + "kMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9u "
                        + "IEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyy"
                        + "qRTImGzHCt kGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7"
                        + "bPhGuEBSjZjBkMB0GA1Ud DgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSME"
                        + "GDAWgBTIrel3TEXDo88NFhDkeUM6IVow zzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA"
                        + "1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBL ipt77oK8wDOHri/AiZi03c"
                        + "ONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsi u+f+uXc/WT/"
                        + "7\n" +
                        "-----END CERTIFICATE-----";
        return createCertificate(certificate);
    }


    /**
     * Creates {@link X509Certificate} from PEM style certificate string.
     *
     * @param derEncodedCertificate DER-encoded certificate. Please note it is encoded in base64 string, not base64url.
     * @return created X509Certificate
     */
    public static X509Certificate createCertificate(String derEncodedCertificate) {
        return CertificateUtil.generateX509Certificate(derEncodedCertificate.getBytes());
    }

    public static CollectedClientData createClientData(ClientDataType type) {
        return createClientData(type, TestUtil.createChallenge());
    }

    public static CollectedClientData createClientData(ClientDataType type, Challenge challenge) {
        return new CollectedClientData(type, challenge, createOrigin(), null);
    }

    public static byte[] createClientDataJSON(ClientDataType type) {
        return new CollectedClientDataConverter(new Registry()).convertToBytes(createClientData(type));
    }

    public static byte[] createClientDataJSON(ClientDataType type, Challenge challenge) {
        return new CollectedClientDataConverter(new Registry()).convertToBytes(createClientData(type, challenge));
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

    public static ServerProperty createRelyingParty() {
        return new ServerProperty(createOrigin(), "localhost", createChallenge(), null);
    }

    public static PrivateKey load3tierTestAuthenticatorAttestationPrivateKey() {
        return loadPrivateKey("classpath:attestation/3tier/private/3tier-test-authenticator.der");
    }

    public static PrivateKey load2tierTestAuthenticatorAttestationPrivateKey() {
        return loadPrivateKey("classpath:attestation/2tier/private/2tier-test-authenticator.der");
    }

    public static PrivateKey loadPrivateKeyFromResource(Resource resource) {
        try {
            InputStream inputStream = resource.getInputStream();
            byte[] data = StreamUtils.copyToByteArray(inputStream);
            return KeyUtil.loadECPrivateKey(data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static PrivateKey loadPrivateKey(String resourcePath) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourcePath);
        return loadPrivateKeyFromResource(resource);
    }

    public static Authenticator createAuthenticator(AttestationObject attestationObject) {
        AttestedCredentialData attestedCredentialData = attestationObject.getAuthenticatorData().getAttestedCredentialData();
        return new AuthenticatorImpl(attestedCredentialData, attestationObject.getAttestationStatement(), attestationObject.getAuthenticatorData().getSignCount());
    }

    public static TrustAnchorResolver createTrustAnchorProviderWith2tierTestRootCACertificate() {
        return (aaguid) -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(load2tierTestRootCACertificate(), null));
            return set;
        };
    }

    public static TrustAnchorResolver createTrustAnchorProviderWith3tierTestRootCACertificate() {
        return (aaguid) -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(load3tierTestRootCACertificate(), null));
            return set;
        };
    }

    public static ServerProperty createServerProperty() {
        return createServerProperty(TestUtil.createChallenge());
    }

    public static ServerProperty createServerProperty(Challenge challenge) {
        return new ServerProperty(TestUtil.createOrigin(), "example.com", challenge, new byte[32]);
    }

    public static Authenticator createAuthenticator(AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement) {
        AuthenticatorImpl authenticator = new AuthenticatorImpl();
        authenticator.setAttestedCredentialData(attestedCredentialData);
        authenticator.setAttestationStatement(attestationStatement);
        authenticator.setCounter(1);
        return authenticator;
    }

    public static Authenticator createAuthenticator() {
        return createAuthenticator(TestUtil.createAttestedCredentialData(), TestUtil.createFIDOU2FAttestationStatement());
    }


    public static byte[] calculateSignature(PrivateKey privateKey, byte[] signedData) {
        try {
            Signature signature;
            if (privateKey.getAlgorithm().equals("EC")) {
                signature = SignatureUtil.getES256();
            } else {
                signature = SignatureUtil.getRS256();
            }
            signature.initSign(privateKey);
            signature.update(signedData);
            return signature.sign();
        } catch (InvalidKeyException | SignatureException e) {
            throw new WebAuthnModelException("Signature calculation error", e);
        }
    }

}
