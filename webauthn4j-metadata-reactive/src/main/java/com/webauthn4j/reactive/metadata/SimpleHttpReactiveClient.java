package com.webauthn4j.reactive.metadata;

import com.webauthn4j.metadata.exception.MDSException;
import org.jetbrains.annotations.NotNull;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletionStage;

public class SimpleHttpReactiveClient implements HttpReactiveClient {
    @Override
    public @NotNull CompletionStage<InputStream> fetch(@NotNull String uri) throws MDSException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .build();
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(HttpResponse::body)
                .exceptionally(e -> {
                    throw new MDSException(e);
                });
    }
}
