/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data;


import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.*;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialTest {

    private final Origin origin = new Origin("http://localhost");
    private final WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
    private final ClientPlatform clientPlatform = new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);

    @Test
    void test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName");

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions
                = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                publicKeyCredentialUserEntity,
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.NONE,
                extensions
        );
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential = clientPlatform.create(credentialCreationOptions);
        //noinspection deprecation
        assertAll(
                () -> assertThat(credential.getType()).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY.getValue()),
                () -> assertThat(credential.getId()).isNotEmpty(),
                () -> assertThat(credential.getRawId()).isNotEmpty(),
                () -> assertThat(credential.getResponse()).isInstanceOf(AuthenticatorAttestationResponse.class),
                () -> assertThat(credential.getResponse()).isInstanceOf(AuthenticatorAttestationResponse.class),
                () -> assertThat(credential.getClientExtensionResults()).isNotNull()
        );
    }

    @Test
    void equals_hashCode_test() {

        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> instanceA = new PublicKeyCredential<>(new byte[32], null, AuthenticatorAttachment.PLATFORM, new AuthenticationExtensionsClientOutputs<>());
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> instanceB = new PublicKeyCredential<>(new byte[32], null, AuthenticatorAttachment.PLATFORM, new AuthenticationExtensionsClientOutputs<>());

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void registrationResponseJSON_deserialization_test() {
        String registrationResponseJSON = "{\"authenticatorAttachment\":\"cross-platform\",\"clientExtensionResults\":{},\"id\":\"1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM\",\"rawId\":\"1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM\",\"response\":{\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgdwS7FNbN3LRg0AQRfDoEqB3dbBhzuUcGhlH6kfXz4eoCIQCzCWskxcpYWa-T1NNUGWv2Pz9PJytnXQSOZN7Z6QpU9GN4NWOBWQHZMIIB1TCCAXqgAwIBAgIBATAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQ1MDMwODEyNDQwM1owYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB_wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSQAwRgIhAJY79PwboVL1bAPx3L7FTthAceD0XPofn7PzdQo2_zOrAiEApqQqSRUDK4zxcGI9LIUJ__3_9dx3HKPOsGZnQpiviNpoYXV0aERhdGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAEBAgMEBQYHCAECAwQFBgcIACDVr97E6utt_Li0NC3DImj8lUC6aEIdd9zY-IOk9OqXE6UBAgMmIAEhWCC5L7pslGp6939rlywpAsF6nsC7AFCyHEa_NtZBX2xGsSJYIPn4dDkPWgF8-8QxTn7cKVHGjWWJ4Z558DO2sqw9mwOM\",\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAINWv3sTq6238uLQ0LcMiaPyVQLpoQh133Nj4g6T06pcTpQECAyYgASFYILkvumyUanr3f2uXLCkCwXqewLsAULIcRr821kFfbEaxIlgg-fh0OQ9aAXz7xDFOftwpUcaNZYnhnnnwM7ayrD2bA4w\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUHlad3lFX1hSYjI1UHM1WHViWmZGUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0\",\"publicKey\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuS-6bJRqevd_a5csKQLBep7AuwBQshxGvzbWQV9sRrH5-HQ5D1oBfPvEMU5-3ClRxo1lieGeefAztrKsPZsDjA\",\"publicKeyAlgorithm\":-7,\"transports\":[\"usb\"]},\"type\":\"public-key\"}";
        ObjectConverter objectConverter = new ObjectConverter();
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> publicKeyCredential = objectConverter.getJsonConverter().readValue(registrationResponseJSON, new TypeReference<>() {});
        assertThat(publicKeyCredential).isNotNull();
        assertThat(publicKeyCredential.getAuthenticatorAttachment()).isEqualTo(AuthenticatorAttachment.CROSS_PLATFORM);
        assertThat(publicKeyCredential.getClientExtensionResults()).isNotNull();
        assertThat(publicKeyCredential.getId()).isEqualTo("1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM");
        assertThat(publicKeyCredential.getRawId()).isEqualTo(Base64UrlUtil.decode("1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM"));
        assertThat(publicKeyCredential.getResponse()).isNotNull();
        assertThat(publicKeyCredential.getType()).isEqualTo("public-key");
    }

    @Test
    void authenticationResponseJSON_deserialization_test() {
        String authenticationResponseJSON = "{\"authenticatorAttachment\":\"cross-platform\",\"clientExtensionResults\":{},\"id\":\"1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM\",\"rawId\":\"1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM\",\"response\":{\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUHlad3lFX1hSYjI1UHM1WHViWmZGUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0\",\"signature\":\"MEUCIQC11ymTM1B0WNHdxgFWxCTnrILBRoLkFMFnusjldBd0yAIgEqwhnPvuIDZczbbxO4BRXNgvX-86PsOMwVpovmhsLFY\",\"userHandle\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"},\"type\":\"public-key\"}";
        ObjectConverter objectConverter = new ObjectConverter();
        PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> publicKeyCredential = objectConverter.getJsonConverter().readValue(authenticationResponseJSON, new TypeReference<>() {});
        assertThat(publicKeyCredential).isNotNull();
        assertThat(publicKeyCredential.getAuthenticatorAttachment()).isEqualTo(AuthenticatorAttachment.CROSS_PLATFORM);
        assertThat(publicKeyCredential.getClientExtensionResults()).isNotNull();
        assertThat(publicKeyCredential.getId()).isEqualTo("1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM");
        assertThat(publicKeyCredential.getRawId()).isEqualTo(Base64UrlUtil.decode("1a_exOrrbfy4tDQtwyJo_JVAumhCHXfc2PiDpPTqlxM"));
        assertThat(publicKeyCredential.getResponse()).isNotNull();
        assertThat(publicKeyCredential.getType()).isEqualTo("public-key");
    }

}