package com.webauthn4j.metadata.http;

import com.webauthn4j.metadata.util.ResourceProvider;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpClientFactoryTest {
    @Test
    void test_http_client_default_config() {
        HttpClient client = HttpClientFactory.createHttpClient();

        assertThat(client instanceof SimpleHttpClient).isTrue();
    }

    @Test
    void test_http_client_with_fallback() throws IOException {
        Properties properties = new Properties();
        properties.setProperty(HttpClientFactory.METADATA_HTTP_CLIENT_IMPL, "does.not.exists.FakeHttpClient");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        properties.store(output, null);
        ByteArrayInputStream is = new ByteArrayInputStream(output.toByteArray());

        ResourceProvider provider = mock(ResourceProvider.class);
        when(provider.resourceAsStream(
                HttpClientFactory.class, HttpClientFactory.METADATA_PROPERTIES)).thenReturn(is);


        HttpClientFactory factory = new HttpClientFactory(provider);

        HttpClient client = factory.createClient();

        assertThat(client instanceof SimpleHttpClient).isTrue();
    }

    /*@Test
    void test_http_client_with_custom_impl() throws IOException {
        Properties properties = new Properties();
        properties.setProperty(HttpClientFactory.METADATA_HTTP_CLIENT_IMPL, "com.webauthn4j.metadata.http.FakeHttpClient");

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        properties.store(output, null);
        ByteArrayInputStream is = new ByteArrayInputStream(output.toByteArray());

        ResourceProvider provider = mock(ResourceProvider.class);
        when(provider.resourceAsStream(
                HttpClientFactory.class, HttpClientFactory.METADATA_PROPERTIES)).thenReturn(is);


        HttpClientFactory factory = new HttpClientFactory(provider);

        HttpClient client = factory.createClient();

        assertThat(client instanceof FakeHttpClient).isTrue();
    }*/
}
