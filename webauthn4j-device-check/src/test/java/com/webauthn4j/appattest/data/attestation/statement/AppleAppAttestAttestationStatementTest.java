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

package com.webauthn4j.appattest.data.attestation.statement;

import com.webauthn4j.appattest.verifier.DCRegistrationObject;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AppleAppAttestAttestationStatementTest {

    @Test
    void constructor_test() {
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath();
        assertAll(
                () -> assertThatThrownBy(() -> new AppleAppAttestAttestationStatement(null, new byte[32])).isInstanceOf(IllegalArgumentException.class),
                () -> assertThatThrownBy(() -> new AppleAppAttestAttestationStatement(attestationCertificatePath, null)).isInstanceOf(IllegalArgumentException.class)
        );
    }

    @Test
    void validate_test() {
        new AppleAppAttestAttestationStatement(new AttestationCertificatePath(), new byte[32]).validate();

    }

    @Test
    void getter_test() {
        DCRegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        AppleAppAttestAttestationStatement appleAppAttestAttestationStatement = (AppleAppAttestAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        assertThat(appleAppAttestAttestationStatement.getX5c()).hasSize(2);
        assertThat(appleAppAttestAttestationStatement.getFormat()).isEqualTo(AppleAppAttestAttestationStatement.FORMAT);
        assertThat(appleAppAttestAttestationStatement.getReceipt()).isEqualTo(Base64UrlUtil.decode("MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwGggCSABIID6DGCBAswIwIBAgIBAQQbOFlFMjNOWlM1Ny5jb20ua2F5YWsudHJhdmVsMIIC7gIBAwIBAQSCAuQwggLgMIICZqADAgECAgYBdNZm2hAwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwOTI3MjAyODE4WhcNMjAwOTMwMjAyODE4WjCBkTFJMEcGA1UEAwxANTY3N2VhOGQyYTc0YWQ2Y2IyYThkODZiN2UxZmJkZmM4ODRiMjJmNWVlNjEzM2MwOTg5MTE1NDMwOTc4NzY0YTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVMXfBQ2n1hERgyf113lWGstIXHIbeiLJi-oIYyZj_aqNGPACJWSmRK_v5B67uZ2bZrNNSoRrwJyoNiwerRvmdo4HqMIHnMAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgTwMHUGCSqGSIb3Y2QIBQRoMGakAwIBCr-JMAMCAQG_iTEDAgEAv4kyAwIBAb-JMwMCAQG_iTQdBBs4WUUyM05aUzU3LmNvbS5rYXlhay50cmF2ZWylBgQEc2tzIL-JNgMCAQW_iTcDAgEAv4k5AwIBAL-JOgMCAQAwGwYJKoZIhvdjZAgHBA4wDL-KeAgEBjE0LjAuMTAzBgkqhkiG92NkCAIEJjAkoSIEIMmvmBS106CCCA0l-C2IhciYKtSnKp-1qGmv597EqyV9MAoGCCqGSM49BAMCA2gAMGUCMQC2xV2A-e9j96iphB6G3Vm53fzMw-lZ_LlgKAHvZy6K3gNCnyMev8_O79TwiHFxBqcCMDwneBrN7P2REtFVdPjdGFSqJQ1AS2VJtX31VRHZzY7FNRLqyTPqkuF9xnay6NWlYzAoAgEEAgEBBCC92s44kCAWK_w87A2CBCqO7rxzyw_c-bUL3gOkdjKdZjBgAgEFAgEBBFgrZVk0U1NuT2pkaWsrWGkzaUJTK1NrR1ZTR004NmlKeVBTYWMrbnUxdU94d2ZvVEFLbXg4U2N0M1hyQmorenYvcE9kVUpodzJ6N3E2SDhHem8vekJtdz09MA4CAQYCAQEEBkFUVEVTVDASAgEHAgEBBApwcm9kdWN0aW9uMCACAQwCAQEEGDIwMjAtMDktMjhUMjA6Mjg6MTkEJy45NDJaMCACARUCAQEEGDIwMjAtMTItMjdUMjA6Mjg6MTkuOTQyWgAAAAAAAKCAMIIDrTCCA1SgAwIBAgIQWTNWreVZgs9EQjes30UbUzAKBggqhkjOPQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMDA1MTkxNzQ3MzFaFw0yMTA2MTgxNzQ3MzFaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR_6RU0bMOKe5g8k9HQQ1_Yq9pWcATTLFiGZVGVerR498sq-LpF9_p46sYsSeT5zcCEtQMU8QIz2pt2-kQqK7hyo4IB2DCCAdQwDAYDVR0TAQH_BAIwADAfBgNVHSMEGDAWgBTZF_5LZ5A4S5L0287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUaR7HD0fs443ddTdE8-nhWmwQViUwDgYDVR0PAQH_BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYIKoZIzj0EAwIDRwAwRAIgJRgWXF4pnFn2hTmtXduZ9jc-9g7NCEWp_Xca1iQtLCICIF0qmypfq6NjgWWNGED3r0gL12uhlNg0IIf01pNbtRuuMIIC-TCCAn-gAwIBAgIQVvuD1Cv_jcM3mSO1Wq5uvTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xOTAzMjIxNzUzMzNaFw0zNDAzMjIwMDAwMDBaMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEks5jvX2GsasoCjsc4a_7BJSAkaz2Md-myyg1b0RL4SHlV90SjY26gnyVvkn6vjPKrs0EGfEvQyX69L6zy4N-uqOB9zCB9DAPBgNVHRMBAf8EBTADAQH_MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ3r6966_ayySrMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYWczMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMB0GA1UdDgQWBBTZF_5LZ5A4S5L0287VV4AUC489yTAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAwQCBQAwCgYIKoZIzj0EAwMDaAAwZQIxAI1vpp-h4OTsW05zipJ_PXhTmI_02h9YHsN1Sv44qEwqgxoaqg2mZG3huZPo0VVM7QIwZzsstOHoNwd3y9XsdqgaOlU7PzVqyMXmkrDhYb6ASWnkXyupbOERAqrMYdk4t3NKMIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX_1H7YyYl3J6YRbTzBPEVoA_VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966_ayySrMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN-yRhHFD_3meoyhpmvOwgPUnPWTxnS4at-qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm-YhidDkLF1vLUagM6BgD56KyKAAAMYIBljCCAZICAQEwgZAwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMCEFkzVq3lWYLPREI3rN9FG1MwDQYJYIZIAWUDBAIBBQCggZUwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwOTI4MjAyODIwWjAqBgkqhkiG9w0BCTQxHTAbMA0GCWCGSAFlAwQCAQUAoQoGCCqGSM49BAMCMC8GCSqGSIb3DQEJBDEiBCDLFFlod6-72Z_XBkt-1Gg9wc1binQgsCMpZ5A1Ge4fnjAKBggqhkjOPQQDAgRHMEUCIQCE46Koolc_FuL29_MUK1Auqt2XUJPK2DD9aDJgbPPKBwIgbsggotsin_9j1y_Z4pBdpYCE6-FY7zCTIp_IaUWymtYAAAAAAAA"));
    }

    @Test
    void equals_hashCode_test() {
        DCRegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        AppleAppAttestAttestationStatement instanceA = (AppleAppAttestAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        DCRegistrationObject registrationObjectB = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        AppleAppAttestAttestationStatement instanceB = (AppleAppAttestAttestationStatement) registrationObjectB.getAttestationObject().getAttestationStatement();

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
