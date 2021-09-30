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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Objects;

/**
 * A WebAuthn Relying Party may require user verification for some of its operations but not for
 * others, and may use this type to express its needs.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#enumdef-userverificationrequirement">
 * §5.10.6. User Verification Requirement Enumeration (enum UserVerificationRequirement)</a>
 */
public class UserVerificationRequirement {

    /**
     * This value indicates that the Relying Party requires user verification for the operation and
     * will fail the operation if the response does not have the UV flag set.
     */
    public static final UserVerificationRequirement REQUIRED = new UserVerificationRequirement("required");

    /**
     * This value indicates that the Relying Party prefers user verification for the operation
     * if possible, but will not fail the operation if the response does not have the UV flag set.
     */
    public static final UserVerificationRequirement PREFERRED = new UserVerificationRequirement("preferred");

    /**
     * This value indicates that the Relying Party does not want user verification employed during
     * the operation (e.g., in the interest of minimizing disruption to the user interaction flow).
     */
    public static final UserVerificationRequirement DISCOURAGED = new UserVerificationRequirement("discouraged");

    private final String value;

    private UserVerificationRequirement(String value) {
        this.value = value;
    }

    @JsonCreator
    public static UserVerificationRequirement create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        switch (value) {
            case "required":
                return REQUIRED;
            case "preferred":
                return PREFERRED;
            case "discouraged":
                return DISCOURAGED;
            default:
                return new UserVerificationRequirement(value);
        }
    }

    @JsonValue
    public @NonNull String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserVerificationRequirement that = (UserVerificationRequirement) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
