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

package com.webauthn4j.converter;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationObjectConverterTest {

    private AttestationObjectConverter target = new AttestationObjectConverter();

    @Test
    public void convert_deserialization_test() {
        String testData = "v2hhdXRoRGF0YVi6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBAAAAAQAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv2ExAGEy9mE09mE19mEzJmItMQFiLTJYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYi0zWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGItNPb_Z2F0dFN0bXS_Y3g1Y59ZAq4wggKqMIIBkqADAgECAhAg92PAQYOxBTfb6FBqIlDuMA0GCSqGSIb3DQEBCwUAMEoxEjAQBgNVBAoMCVNoYXJwTGFiLjE0MDIGA1UEAwwrc3ByaW5nLXNlY3VyaXR5LXdlYmF1dGhuIDJ0aWVyIHRlc3Qgcm9vdCBDQTAgFw0xODA1MDExMzUyMjBaGA8yMTE4MDQwNzEzNTIyMFowYDEOMAwGA1UECAwFVG9reW8xEjAQBgNVBAoMCVNoYXJwTGFiLjE6MDgGA1UEAwwxc3ByaW5nLXNlY3VyaXR5LXdlYmF1dGhuIDJ0aWVyIHRlc3QgYXV0aGVudGljYXRvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGDnW6yJjgII2Td12_Lp3xx4SQyDXSMpKJbfsqRsXK6KeCsG7o19s76ERmb3aEPZrvq8IwGbeB90jLEsT7wfM_CjPzA9MAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgeAMB0GA1UdDgQWBBTQ686zWmmu7HTEfbs7LzvDqIXY4TANBgkqhkiG9w0BAQsFAAOCAQEAmWeVM_8U33unytwLJLgTUyUSmf8tEMO8CJnFEk73YZl2Co5BMRyApSHRGJust2EplKX-pz5hVqC0eJVrHbXEfFtKjxe8oW2Kst_Zu6S0WfvLPH7ESAPBTh2GG8TrSAbnQ12zGvsAVTgY3lGUTLp8l7FHbpK2ktpPObJkZJ3CMaMo9RjFg1Y4p4F3mVfV4pYN3y-xNSxdg9kW8D4gMWeqy4rASgF4MVe7zOVZ6N_eCnsWg8DXPigXC480oEwdnDfqNv--ZWV8UCRYN7kyfIOw6OFPlb7J_FACTG37zz0H6qgCzrbXfUlWoGqQRQ70Rd4lQnss_M9gDL8UNFD9JIJ3Jf9jc2lnWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9jZm10aGZpZG8tdTJm_w";
        AttestationObject attestationObject = target.convert(testData);
        AuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();
        String format = attestationObject.getFormat();
        AttestationStatement attestationStatement = attestationObject.getAttestationStatement();

        assertThat(authenticatorData).isNotNull();
        assertThat(format).isEqualTo("fido-u2f");
        assertThat(attestationStatement).isInstanceOf(FIDOU2FAttestationStatement.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void convert_test_with_illegal_input() {
        String testData = "illegal input";
        target.convert(testData);
    }

    @Test
    public void convert_serialization_test() {
        AttestationObject input = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        String result = target.convertToString(input);
        AttestationObject deserialized = target.convert(result);
        assertThat(deserialized).isEqualTo(input);
    }


}
