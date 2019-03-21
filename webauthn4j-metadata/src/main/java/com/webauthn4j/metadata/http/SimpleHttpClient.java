/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.metadata.http;

import com.webauthn4j.metadata.exception.MDSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Tiny implementation of {@link HttpClient}. If you prefer more powerful one, implement {@link HttpClient} with
 * your favorite HTTP client library.
 */
public class SimpleHttpClient implements HttpClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleHttpClient.class);

    public SimpleHttpClient() {
    }

    @Override
    public String fetch(String url) throws MDSException {
        try {
            URL fetchUrl = new URL(url);
            HttpURLConnection urlConnection = (HttpURLConnection) fetchUrl.openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.connect();

            int status = urlConnection.getResponseCode();

            if (status == HttpURLConnection.HTTP_OK) {
                InputStream inputStream = urlConnection.getInputStream();
                BufferedInputStream bis = new BufferedInputStream(inputStream);
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                int result = bis.read();
                while (result != -1) {
                    buf.write((byte) result);
                    result = bis.read();
                }
                bis.close();
                return buf.toString("UTF-8");
            } else {
                String message = urlConnection.getResponseMessage();

                throw new MDSException("Unable to connect to '" + url + "'"
                        + ", responded with status: " + status
                        + ", message: '" + message + "'");
            }
        } catch (IOException e) {
            LOGGER.error("Unable to retrieve MDS data from '" + url + "'", e);

            throw new MDSException("Unable to connect to '" + url + "'", e);
        }
    }

    @Override
    public void close() throws Exception {
        // Not used in this implementation
    }
}
