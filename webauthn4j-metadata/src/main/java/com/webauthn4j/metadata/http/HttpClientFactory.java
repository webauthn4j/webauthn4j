package com.webauthn4j.metadata.http;

import com.webauthn4j.metadata.util.ResourceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class HttpClientFactory {
    final static String METADATA_PROPERTIES = "webauthn4j-metadata.properties";
    final static String METADATA_HTTP_CLIENT_IMPL = "webauthn4j.metadata.httpclient.impl";
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);
    private String implementationClassName = SimpleHttpClient.class.getCanonicalName();

    HttpClientFactory(ResourceProvider provider) {
        InputStream resource = provider.resourceAsStream(this.getClass(), METADATA_PROPERTIES);

        if (null != resource) {
            try {
                Properties props = new Properties();
                props.load(resource);

                if (props.containsKey(METADATA_HTTP_CLIENT_IMPL)) {
                    implementationClassName = props.getProperty(METADATA_HTTP_CLIENT_IMPL, SimpleHttpClient.class.getCanonicalName());
                }

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Using HttpClient implementation: '" + implementationClassName + "'");
                }
            } catch (IOException e) {
                LOGGER.error("Unable to load properties from '" + METADATA_PROPERTIES + "'. Current HttpClient implementation would be: '" + implementationClassName + "'");
            }
        }
    }

    public static HttpClient createHttpClient() {
        return new HttpClientFactory(new ResourceProviderImpl()).createClient();
    }

    HttpClient createClient() {
        try {
            Class<?> aClass = Class.forName(this.implementationClassName);

            // Check if the HttpClient interface is implemented
            if (HttpClient.class.isAssignableFrom(aClass)) {
                return (HttpClient) aClass.newInstance();
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOGGER.error("Unable to create new instance of the HttpClient. Falling back to SimpleHttpClient.", e);
        }

        return new SimpleHttpClient();
    }

    static class ResourceProviderImpl implements ResourceProvider {
        @Override
        public InputStream resourceAsStream(Class<?> c, String fileName) {
            return c.getClassLoader().getResourceAsStream(fileName);
        }
    }
}
