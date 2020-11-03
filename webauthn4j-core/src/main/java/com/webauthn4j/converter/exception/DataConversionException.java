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

package com.webauthn4j.converter.exception;

import com.webauthn4j.util.exception.WebAuthnException;
import org.checkerframework.checker.nullness.qual.Nullable;

public class DataConversionException extends WebAuthnException {

    public DataConversionException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public DataConversionException(@Nullable String message) {
        super(message);
    }

    public DataConversionException(@Nullable Throwable cause) {
        super(cause);
    }
}
