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

package com.webauthn4j.appattest;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.appattest.data.*;
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;

class DeviceCheckManagerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    private final AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
    private final AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);

    @Test
    void parse_attestation_test() {

        TrustAnchorRepository trustAnchorRepository = getAppleAppAttestCertFileTrustAnchorsRepository();
        DeviceCheckManager deviceCheckManager = new DeviceCheckManager(new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository));

        byte[] keyId = Base64Util.decode("VnfqjSp0rWyyqNhrfh+9/IhLIvXuYTPAmJEVQwl4dko=");
        byte[] attestationObject = Base64Util.decode("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");
        byte[] challenge = "1234567890abcdefgh".getBytes();
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);

        DCAttestationRequest dcAttestationRequest = new DCAttestationRequest(keyId, attestationObject, clientDataHash);

        DCAttestationData dcAttestationData = deviceCheckManager.parse(dcAttestationRequest);
        assertThat(dcAttestationData.getKeyId()).isEqualTo(keyId);
        assertThat(dcAttestationData.getAttestationObject()).isInstanceOf(AttestationObject.class);
        assertThat(dcAttestationData.getAttestationObjectBytes()).isEqualTo(attestationObject);
        assertThat(dcAttestationData.getClientDataHash()).isEqualTo(clientDataHash);
    }


    @Test
    void validate_attestation_test() {

        byte[] keyId = Base64Util.decode("VnfqjSp0rWyyqNhrfh+9/IhLIvXuYTPAmJEVQwl4dko=");
        byte[] attestationObject = Base64Util.decode("o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAuQwggLgMIICZqADAgECAgYBdNZm2hAwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwOTI3MjAyODE4WhcNMjAwOTMwMjAyODE4WjCBkTFJMEcGA1UEAwxANTY3N2VhOGQyYTc0YWQ2Y2IyYThkODZiN2UxZmJkZmM4ODRiMjJmNWVlNjEzM2MwOTg5MTE1NDMwOTc4NzY0YTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVMXfBQ2n1hERgyf113lWGstIXHIbeiLJi+oIYyZj/aqNGPACJWSmRK/v5B67uZ2bZrNNSoRrwJyoNiwerRvmdo4HqMIHnMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMHUGCSqGSIb3Y2QIBQRoMGakAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIBAb+JMwMCAQG/iTQdBBs4WUUyM05aUzU3LmNvbS5rYXlhay50cmF2ZWylBgQEc2tzIL+JNgMCAQW/iTcDAgEAv4k5AwIBAL+JOgMCAQAwGwYJKoZIhvdjZAgHBA4wDL+KeAgEBjE0LjAuMTAzBgkqhkiG92NkCAIEJjAkoSIEIMmvmBS106CCCA0l+C2IhciYKtSnKp+1qGmv597EqyV9MAoGCCqGSM49BAMCA2gAMGUCMQC2xV2A+e9j96iphB6G3Vm53fzMw+lZ/LlgKAHvZy6K3gNCnyMev8/O79TwiHFxBqcCMDwneBrN7P2REtFVdPjdGFSqJQ1AS2VJtX31VRHZzY7FNRLqyTPqkuF9xnay6NWlY1kCRzCCAkMwggHIoAMCAQICEAm6xeG8QBrZ1FOVvDgaCFQwCgYIKoZIzj0EAwMwUjEmMCQGA1UEAwwdQXBwbGUgQXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzOTU1WhcNMzAwMzEzMDAwMDAwWjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK5bN6B3TXmyNY9A59HyJibxwl/vF4At6rOCalmHT/jSrRUleJqiZgQZEki2PLlnBp6Y02O9XjcPv6COMp6Ac6mF53Ruo1mi9m8p2zKvRV4hFljVZ6+eJn6yYU3CGmbOmaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSskRBTM72+aEH/pwyp5frq5eWKoTAdBgNVHQ4EFgQUPuNdHAQZqcm0MfiEdNbh4Vdy45swDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2kAMGYCMQC7voiNc40FAs+8/WZtCVdQNbzWhyw/hDBJJint0fkU6HmZHJrota7406hUM/e2DQYCMQCrOO3QzIHtAKRSw7pE+ZNjZVP+zCl/LrTfn16+WkrKtplcS4IN+QQ4b3gHu1iUObdncmVjZWlwdFkO6jCABgkqhkiG9w0BBwKggDCAAgEBMQ8wDQYJYIZIAWUDBAIBBQAwgAYJKoZIhvcNAQcBoIAkgASCA+gxggQLMCMCAQICAQEEGzhZRTIzTlpTNTcuY29tLmtheWFrLnRyYXZlbDCCAu4CAQMCAQEEggLkMIIC4DCCAmagAwIBAgIGAXTWZtoQMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDkyNzIwMjgxOFoXDTIwMDkzMDIwMjgxOFowgZExSTBHBgNVBAMMQDU2NzdlYThkMmE3NGFkNmNiMmE4ZDg2YjdlMWZiZGZjODg0YjIyZjVlZTYxMzNjMDk4OTExNTQzMDk3ODc2NGExGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElTF3wUNp9YREYMn9dd5VhrLSFxyG3oiyYvqCGMmY/2qjRjwAiVkpkSv7+Qeu7mdm2azTUqEa8CcqDYsHq0b5naOB6jCB5zAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DB1BgkqhkiG92NkCAUEaDBmpAMCAQq/iTADAgEBv4kxAwIBAL+JMgMCAQG/iTMDAgEBv4k0HQQbOFlFMjNOWlM1Ny5jb20ua2F5YWsudHJhdmVspQYEBHNrcyC/iTYDAgEFv4k3AwIBAL+JOQMCAQC/iToDAgEAMBsGCSqGSIb3Y2QIBwQOMAy/ingIBAYxNC4wLjEwMwYJKoZIhvdjZAgCBCYwJKEiBCDJr5gUtdOggggNJfgtiIXImCrUpyqftahpr+fexKslfTAKBggqhkjOPQQDAgNoADBlAjEAtsVdgPnvY/eoqYQeht1Zud38zMPpWfy5YCgB72cuit4DQp8jHr/Pzu/U8IhxcQanAjA8J3gazez9kRLRVXT43RhUqiUNQEtlSbV99VUR2c2OxTUS6skz6pLhfcZ2sujVpWMwKAIBBAIBAQQgvdrOOJAgFiv8POwNggQqju68c8sP3Pm1C94DpHYynWYwYAIBBQIBAQRYK2VZNFNTbk9qZGlrK1hpM2lCUytTa0dWU0dNODZpSnlQU2FjK251MXVPeHdmb1RBS214OFNjdDNYckJqK3p2L3BPZFVKaHcyejdxNkg4R3pvL3pCbXc9PTAOAgEGAgEBBAZBVFRFU1QwEgIBBwIBAQQKcHJvZHVjdGlvbjAgAgEMAgEBBBgyMDIwLTA5LTI4VDIwOjI4OjE5BCcuOTQyWjAgAgEVAgEBBBgyMDIwLTEyLTI3VDIwOjI4OjE5Ljk0MloAAAAAAACggDCCA60wggNUoAMCAQICEFkzVq3lWYLPREI3rN9FG1MwCgYIKoZIzj0EAwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjAwNTE5MTc0NzMxWhcNMjEwNjE4MTc0NzMxWjBaMTYwNAYDVQQDDC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf+kVNGzDinuYPJPR0ENf2KvaVnAE0yxYhmVRlXq0ePfLKvi6Rff6eOrGLEnk+c3AhLUDFPECM9qbdvpEKiu4cqOCAdgwggHUMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU2Rf+S2eQOEuS9NvO1VeAFAuPPckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB/TCBwwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFGkexw9H7OON3XU3RPPp4VpsEFYlMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0cAMEQCICUYFlxeKZxZ9oU5rV3bmfY3PvYOzQhFqf13GtYkLSwiAiBdKpsqX6ujY4FljRhA969IC9droZTYNCCH9NaTW7UbrjCCAvkwggJ/oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv+wSUgJGs9jHfpssoNW9ES+Eh5VfdEo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcwgfQwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVyb290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAdBgNVHQ4EFgQU2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9NofWB7DdUr+OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG+gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjSxUuVMAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x3BQW2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv2sskqzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg+nBxBZeGl00GNnt7/RsDgBGS7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/NjUM+tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA+eisigAADGCAZYwggGSAgEBMIGQMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTAhBZM1at5VmCz0RCN6zfRRtTMA0GCWCGSAFlAwQCAQUAoIGVMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIwMDkyODIwMjgyMFowKgYJKoZIhvcNAQk0MR0wGzANBglghkgBZQMEAgEFAKEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQgyxRZaHevu9mf1wZLftRoPcHNW4p0ILAjKWeQNRnuH54wCgYIKoZIzj0EAwIERzBFAiEAhOOiqKJXPxbi9vfzFCtQLqrdl1CTytgw/WgyYGzzygcCIG7IIKLbIp//Y9cv2eKQXaWAhOvhWO8wkyKfyGlFsprWAAAAAAAAaGF1dGhEYXRhWKQwYALKBV4GxYilLsaqVIL1No4CrzCHsenTCdBAyvXZWkAAAAAAYXBwYXR0ZXN0AAAAAAAAAAAgVnfqjSp0rWyyqNhrfh+9/IhLIvXuYTPAmJEVQwl4dkqlAQIDJiABIVgglTF3wUNp9YREYMn9dd5VhrLSFxyG3oiyYvqCGMmY/2oiWCCjRjwAiVkpkSv7+Qeu7mdm2azTUqEa8CcqDYsHq0b5nQ==");
        byte[] challenge = "1234567890abcdefgh".getBytes();
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);

        TrustAnchorRepository trustAnchorRepository = getAppleAppAttestCertFileTrustAnchorsRepository();

        DeviceCheckManager deviceCheckManager = new DeviceCheckManager(new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository));

        DCServerProperty dcServerProperty = new DCServerProperty("8YE23NZS57.com.kayak.travel", new DefaultChallenge(challenge));
        DCAttestationRequest dcAttestationRequest = new DCAttestationRequest(keyId, attestationObject, clientDataHash);
        DCAttestationParameters dcAttestationParameters = new DCAttestationParameters(dcServerProperty);

        Instant timestamp = Instant.parse("2020-09-28T00:00:00Z");
        try (MockedStatic<Instant> mocked = mockStatic(Instant.class)) {
            mocked.when(Instant::now).thenReturn(timestamp);

            // When Apple App Attest Root Certificate is not set, throws CertificateException
            DCAttestationData dcAttestationData = deviceCheckManager.validate(dcAttestationRequest, dcAttestationParameters);
        }
    }

    @Test
    void parse_assertion_test() {
        DeviceCheckManager deviceCheckManager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        byte[] keyId = Base64Util.decode("VnfqjSp0rWyyqNhrfh+9/IhLIvXuYTPAmJEVQwl4dko=");
        byte[] assertion = Base64Util.decode("omlzaWduYXR1cmVYRjBEAiB4zR/olM8j24vmT3fGVA1eykitnp/jpMG9sM6CNsF2lQIgVCK5x6m/jkocPmX6wuPqlJ8tzbvI9bQnd8XYebJ8XuBxYXV0aGVudGljYXRvckRhdGFYJTBgAsoFXgbFiKUuxqpUgvU2jgKvMIex6dMJ0EDK9dlaQAAAAAE=");

        byte[] challenge = "1234567890abcdefgh".getBytes();
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);
        DCAssertionRequest dcAssertionRequest = new DCAssertionRequest(keyId, assertion, clientDataHash);

        DCAssertionData dcAssertionData = deviceCheckManager.parse(dcAssertionRequest);
        assertThat(dcAssertionData.getCredentialId()).isEqualTo(keyId);
        assertThat(dcAssertionData.getAuthenticatorDataBytes()).isEqualTo(Base64UrlUtil.decode("MGACygVeBsWIpS7GqlSC9TaOAq8wh7Hp0wnQQMr12VpAAAAAAQ"));
        assertThat(dcAssertionData.getClientDataHash()).isEqualTo(Base64UrlUtil.decode("vdrOOJAgFiv8POwNggQqju68c8sP3Pm1C94DpHYynWY"));
    }

    @Test
    void validate_assertion_test() {
        DeviceCheckManager deviceCheckManager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        byte[] keyId = Base64Util.decode("VnfqjSp0rWyyqNhrfh+9/IhLIvXuYTPAmJEVQwl4dko=");
        byte[] assertion = Base64Util.decode("omlzaWduYXR1cmVYRjBEAiB4zR/olM8j24vmT3fGVA1eykitnp/jpMG9sM6CNsF2lQIgVCK5x6m/jkocPmX6wuPqlJ8tzbvI9bQnd8XYebJ8XuBxYXV0aGVudGljYXRvckRhdGFYJTBgAsoFXgbFiKUuxqpUgvU2jgKvMIex6dMJ0EDK9dlaQAAAAAE=");

        byte[] challenge = "1234567890abcdefgh".getBytes();
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);
        DCAssertionRequest dcAssertionRequest = new DCAssertionRequest(keyId, assertion, clientDataHash);
        DCServerProperty dcServerProperty = new DCServerProperty("8YE23NZS57.com.kayak.travel", new DefaultChallenge(challenge));

        byte[] attestationObjectBytes = Base64Util.decode("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");
        byte[] authenticatorDataBytes = attestationObjectConverter.extractAuthenticatorData(attestationObjectBytes);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);
        byte[] attestedCredentialDataBytes = authenticatorDataConverter.extractAttestedCredentialData(authenticatorDataBytes);
        AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(attestedCredentialDataBytes);
        byte[] attestationStatementBytes = attestationObjectConverter.extractAttestationStatement(attestationObjectBytes);
        AppleAppAttestAttestationStatement attestationStatement = objectConverter.getCborConverter().readValue(attestationStatementBytes, AppleAppAttestAttestationStatement.class);
        long counter = authenticatorData.getSignCount();

        DCAppleDevice dcAppleDevice = new DCAppleDeviceImpl(attestedCredentialData, attestationStatement, counter, new AuthenticationExtensionsAuthenticatorOutputs<>());
        DCAssertionParameters dcAssertionParameters = new DCAssertionParameters(dcServerProperty, dcAppleDevice);

        deviceCheckManager.validate(dcAssertionRequest, dcAssertionParameters);

    }

    @Test
    void getter_test() {
        DeviceCheckManager deviceCheckManager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        assertThat(deviceCheckManager.getAttestationDataValidator()).isNotNull();
        assertThat(deviceCheckManager.getAssertionDataValidator()).isNotNull();
    }

    private TrustAnchorRepository getAppleAppAttestCertFileTrustAnchorsRepository() {
        return new TrustAnchorRepository() {
            @Override
            public Set<TrustAnchor> find(AAGUID aaguid) {
                Set<TrustAnchor> set = new HashSet<>();
                set.add(new TrustAnchor(loadCertificateFromClassPath("apple-app-attest/Apple_App_Attestation_Root_CA.pem"), null));
                return set;
            }

            @Override
            public Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier) {
                Set<TrustAnchor> set = new HashSet<>();
                set.add(new TrustAnchor(loadCertificateFromClassPath("apple-app-attest/Apple_App_Attestation_Root_CA.pem"), null));
                return set;
            }
        };
    }

    private static X509Certificate loadCertificateFromClassPath(String classPath) {
        try(InputStream inputStream = ClassLoader.getSystemResource(classPath).openStream()){
            return CertificateUtil.generateX509Certificate(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}