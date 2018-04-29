package com.webauthn4j.converter;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.DefaultChallenge;
import org.junit.Ignore;
import org.junit.Test;

import java.util.HashMap;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_GET;
import static org.assertj.core.api.Assertions.assertThat;

public class CollectedClientDataConverterTest {

    private CollectedClientDataConverter target = new CollectedClientDataConverter();

    @Ignore
    @Test
    public void convert_deserialization_test() {
        String clientDataBase64UrlString = "eyJjaGFsbGVuZ2UiOiJ0azMxVUgxRVRHR1RQajMzT2hPTXp3IiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9";
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        CollectedClientData expected = new CollectedClientData(TYPE_WEBAUTHN_GET,
                new DefaultChallenge("tk31UH1ETGGTPj33OhOMzw"),
                new Origin("http://localhost:8080"),
                null);
        assertThat(collectedClientData).isEqualToComparingFieldByFieldRecursively(expected);
    }
}
