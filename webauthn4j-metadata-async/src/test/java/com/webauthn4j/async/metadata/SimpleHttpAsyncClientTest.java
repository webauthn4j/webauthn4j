package com.webauthn4j.async.metadata;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

class SimpleHttpAsyncClientTest {

    private final SimpleHttpAsyncClient target = new SimpleHttpAsyncClient();

    @Test
    void test() throws ExecutionException, InterruptedException {
        InputStream inputStream = target.fetch("https://github.com/webauthn4/webauthn4j").toCompletableFuture().get().getBody();
        assertThat(inputStream).asString(StandardCharsets.UTF_8).contains("webauthn4j");
    }

}