package com.webauthn4j.async.util.internal;


import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

class FileAsyncUtilTest {

    @Test
    void test() throws URISyntaxException, ExecutionException, InterruptedException {
        Path path = Paths.get(ClassLoader.getSystemResource("com/webauthn4j/async/anchor/KeyStoreTrustAnchorAsyncRepositoryTest/test.jks").toURI());
        byte[] bytes = FileAsyncUtil.load(path).toCompletableFuture().get();
        assertThat(bytes).hasSize(451);
    }

}