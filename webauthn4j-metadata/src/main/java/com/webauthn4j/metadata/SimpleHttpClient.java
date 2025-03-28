/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.metadata;

import com.webauthn4j.metadata.exception.MDSException;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Tiny implementation of {@link HttpClient}. If you prefer more powerful one, implement {@link HttpClient} with
 * your favorite HTTP client library.
 */
public class SimpleHttpClient implements HttpClient {

    @Override
    public @NotNull Response fetch(@NotNull String url) {
        try {
            URL fetchUrl = new URL(url);
            HttpURLConnection urlConnection = (HttpURLConnection) fetchUrl.openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.connect();

            int status = urlConnection.getResponseCode();

            if (status == HttpURLConnection.HTTP_OK) {
                InputStream inputStream = urlConnection.getInputStream();
                return new Response(status, inputStream);
            }
            throw new MDSException("failed to fetch " + url);
        } catch (IOException e) {
            throw new MDSException("failed to fetch " + url, e);
        }
    }
}
