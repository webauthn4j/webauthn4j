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
import com.webauthn4j.registry.Registry;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationObjectConverterTest {

    private Registry registry = new Registry();
    private AttestationObjectConverter target = new AttestationObjectConverter(registry);

    @Test
    public void convert_deserialization_test() {
        String testData = "v2hhdXRoRGF0YVi6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBAAAAAQAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv2ExYTJhMvZhMyZhNPZhNfZiLTEBYi0yWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGItM1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhMQL_Z2F0dFN0bXS_Y3g1Y4FZAsswggLHMIIBr6ADAgECAhAg92PAQYOxBTfb6FBqIlDyMA0GCSqGSIb3DQEBCwUAMEoxEjAQBgNVBAoMCVNoYXJwTGFiLjE0MDIGA1UEAwwrc3ByaW5nLXNlY3VyaXR5LXdlYmF1dGhuIDJ0aWVyIHRlc3Qgcm9vdCBDQTAgFw0xODA1MjAwNzA5NTVaGA8yMTE4MDQyNjA3MDk1NVowfTELMAkGA1UEBhMCSlAxEjAQBgNVBAoMCVNoYXJwTGFiLjEgMB4GA1UECwwXQXR0ZXN0YXRpb24gQ2VydGlmaWNhdGUxODA2BgNVBAMML3dlYmF1dGhuNGogdGVzdCAydGllciBhdXRoZW50aWNhdG9yIGF0dGVzdGF0aW9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYOdbrImOAgjZN3Xb8unfHHhJDINdIykolt-ypGxcrop4KwbujX2zvoRGZvdoQ9mu-rwjAZt4H3SMsSxPvB8z8KM_MD0wDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFNDrzrNaaa7sdMR9uzsvO8OohdjhMA0GCSqGSIb3DQEBCwUAA4IBAQCtHcryqNSHDyszLtIByc5AzPam37vl0AVchb0qOxLFbmdUu4Nhzk-87YdA_VZuvVLInsIGaCwkP3rdqGAFY1HllglMnmWIoG2sKjmT3vpJydlDODaha9F_fVG7cq2i5Zx2KMTeUtuTkNdZDjocUUHXYVShgNnggoUWkVeLBG1ckzK1tAkbUwyChWMv4PDmIUBNv6DwkYI9oBSCSAJHpUzyxzMvCRbAFAICwPl3g-SQEUeiNlnzJuGXHnHxu-DB6JD2b0hPeYD6XxWPuI0Pq1G_6hGQmsNv3SF2ye2y_HOKnw3L-fzRHl5ksOdVZbpy9xXzTdIBUpvTmFuwcBo4HwRMY3NpZ1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD_Y2ZtdGhmaWRvLXUyZv8";
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
