package com.webauthn4j.metadata.util;

import java.io.InputStream;

public interface ResourceProvider {
    InputStream resourceAsStream(Class<?> c, String fileName);
}
