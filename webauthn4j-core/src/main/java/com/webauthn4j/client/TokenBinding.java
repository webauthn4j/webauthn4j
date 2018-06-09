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

package com.webauthn4j.client;

import com.webauthn4j.util.Base64UrlUtil;

import java.io.Serializable;
import java.util.Objects;

public class TokenBinding implements Serializable {

    private TokenBindingStatus status;
    private String id;

    public TokenBinding(TokenBindingStatus status, String id) {
        this.status = status;
        this.id = id;
    }

    public TokenBinding(TokenBindingStatus status, byte[] id) {
        this.status = status;
        if (id == null) {
            this.id = null;
        } else {
            this.id = Base64UrlUtil.encodeToString(id);
        }
    }

    public TokenBinding() {
    }

    public TokenBindingStatus getStatus() {
        return status;
    }

    public String getId() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenBinding that = (TokenBinding) o;
        return status == that.status &&
                Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {

        return Objects.hash(status, id);
    }
}
