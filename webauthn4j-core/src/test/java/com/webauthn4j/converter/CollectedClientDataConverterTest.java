package com.webauthn4j.converter;

import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class CollectedClientDataConverterTest {

    private CollectedClientDataConverter target = new CollectedClientDataConverter();

    @Test
    public void convert_deserialization_test() {
        String clientDataJson = "{\"challenge\":\"tk31UH1ETGGTPj33OhOMzw\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.get\"}";
        String clientDataBase64UrlString = Base64UrlUtil.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.GET);
        assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("tk31UH1ETGGTPj33OhOMzw"));
        assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("http://localhost:8080"));
    }

    @Test
    public void convert_clientDataBase64UrlString_with_new_keys_test() {
        String clientDataJson = "{\"challenge\":\"Tgup0LZZQKinvtQcZFYdRw\",\"new_keys_may_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.create\"}";
        String clientDataBase64UrlString = Base64UrlUtil.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.CREATE);
        assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("Tgup0LZZQKinvtQcZFYdRw"));
        assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("http://localhost:8080"));
    }

    @Test
    public void convertToString_deserialization_test() {
        String clientDataJson = "{\"challenge\":\"tk31UH1ETGGTPj33OhOMzw\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.get\"}";
        String clientDataBase64UrlString = Base64UrlUtil.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        String result = target.convertToString(collectedClientData);
        assertThat(result).isEqualTo("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGszMVVIMUVUR0dUUGozM09oT016dyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInRva2VuQmluZGluZyI6eyJzdGF0dXMiOiJub3Qtc3VwcG9ydGVkIiwiaWQiOm51bGx9fQ");
    }
}
