package com.webauthn4j.async.metadata;

import com.webauthn4j.metadata.exception.MDSException;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletionStage;

public class SimpleHttpAsyncClient implements HttpAsyncClient {
    @Override
    public @NotNull CompletionStage<com.webauthn4j.metadata.HttpClient.Response> fetch(@NotNull String uri) throws MDSException {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .timeout(Duration.ofSeconds(60))
                .build();
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(response -> new com.webauthn4j.metadata.HttpClient.Response(response.statusCode(), response.body()))
                .exceptionally(e -> {
                    throw new MDSException(e);
                });
    }
}
