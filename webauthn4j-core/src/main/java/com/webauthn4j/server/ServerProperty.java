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

package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Data transfer object that represents relying party server property for verifiers
 */
public class ServerProperty extends CoreServerProperty {

    // ~ Instance fields
    // ================================================================================================

    private final OriginPredicate originPredicate;
    private final OriginPredicate topOriginPredicate;
    private final byte[] tokenBindingId;

    // For backward compatibility
    private Set<Origin> origins = Collections.emptySet();

    // ~ Builder
    // ========================================================================================================

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private OriginPredicate originPredicate;
        private String rpId;
        private Challenge challenge;
        private OriginPredicate topOriginPredicate;

        private Builder() {}

        /**
         * Sets an originPredicate that accepts the specified origin.
         * For complicated conditions, use {@link #originPredicate(OriginPredicate)} instead.
         *
         * @param value the expected origin
         * @return the builder instance for method chaining
         */
        public Builder origin(@NotNull Origin value) {
            AssertUtil.notNull(value, "value must not be null");
            this.originPredicate = new SimpleOriginPredicate(value);
            return this;
        }

        /**
         * Sets an originPredicate that accepts the specified origins.
         * For complicated conditions, use {@link #originPredicate(OriginPredicate)} instead.
         *
         * @param value the expected origin
         * @return the builder instance for method chaining
         */
        public Builder origins(@NotNull Set<Origin> value) {
            AssertUtil.notNull(value, "value must not be null");
            AssertUtil.notEmpty(value, "value must not be empty");
            this.originPredicate = new SimpleOriginPredicate(value);
            return this;
        }

        
        /**
         * Sets a predicate to verify the origin.
         * This allows for complex origin validation logic beyond simple equality or set membership checks.
         *
         * @param value the predicate used to validate origins
         * @return the builder instance for method chaining
         */
        public Builder originPredicate(@NotNull OriginPredicate value) {
            AssertUtil.notNull(value, "value must not be null");
            this.originPredicate = value;
            return this;
        }


        /**
         * Sets the expected Relying Party ID.
         *
         * @param value the rpId value
         * @return the builder instance for method chaining
         */
        public Builder rpId(String value) {
            this.rpId = value;
            return this;
        }

        /**
         * Sets the expected challenge
         *
         * @param value the challenge value
         * @return the builder instance for method chaining
         */
        public Builder challenge(Challenge value) {
            this.challenge = value;
            return this;
        }

        /**
         * Sets a topOriginPredicate that accepts the specified topOrigin.
         * For complicated conditions, use {@link #topOriginPredicate(OriginPredicate)} instead.
         *
         * @param value the expected topOrigin
         * @return the builder instance for method chaining
         */
        public Builder topOrigin(@Nullable Origin value) {
            if(value == null){
                this.topOriginPredicate = new NoOriginPredicate();
            }
            else{
                this.topOriginPredicate = new SimpleOriginPredicate(value);
            }
            return this;
        }

        /**
         * Sets a topOriginPredicate that accepts the specified topOrigins.
         * For complicated conditions, use {@link #topOriginPredicate(OriginPredicate)} instead.
         *
         * @param value the expected topOrigin
         * @return the builder instance for method chaining
         */
        public Builder topOrigins(@Nullable Set<Origin> value) {
            if(value == null || value.isEmpty()){
                this.topOriginPredicate = new NoOriginPredicate();
            }
            else {
                this.topOriginPredicate = new SimpleOriginPredicate(value);
            }
            return this;
        }


        /**
         * Sets a topOriginPredicate that accepts any topOrigins.
         * This allows WebAuthn operations in any iframe scenario regardless of the top origin.
         *
         * @return the builder instance for method chaining
         */
        public Builder anyTopOrigin() {
            this.topOriginPredicate = new AnyOriginPredicate();
            return this;
        }

        /**
         * Sets a predicate to verify the topOrigin.
         * This allows verification of the top origin in iframe scenarios.
         * If not called or null is passed, cross-origin requests in an iframe will not be allowed.
         *
         * @param value the predicate used to verify top origin. If null, cross-origin requests will not be allowed.
         * @return the builder instance for method chaining
         */
        public Builder topOriginPredicate(OriginPredicate value) {
            this.topOriginPredicate = value;
            return this;
        }

        public ServerProperty build() {
            AssertUtil.notNull(originPredicate, "originPredicate must not be null. Use origin(), origins() or originPredicate() to set it");
            AssertUtil.notNull(rpId, "rpId must not be null");
            return new ServerProperty(originPredicate, rpId, challenge, topOriginPredicate);
        }
    }


    // ~ Constructor
    // ========================================================================================================

    /**
     * @param originPredicate         origin predicate
     * @param rpId           rpId
     * @param challenge      challenge
     */
    private ServerProperty(@NotNull OriginPredicate originPredicate, @NotNull String rpId, @Nullable Challenge challenge, @Nullable OriginPredicate topOriginPredicate) {
        super(rpId, challenge);
        AssertUtil.notNull(originPredicate, "originPredicate must not be null");
        this.originPredicate = originPredicate;
        this.tokenBindingId = null;
        this.topOriginPredicate = topOriginPredicate;
    }

    /**
     * @param originPredicate         origin predicate
     * @param rpId           rpId
     * @param challenge      challenge
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3. Use {@link Builder} instead
     */
    @Deprecated
    private ServerProperty(@NotNull OriginPredicate originPredicate, @NotNull String rpId, @Nullable Challenge challenge, @Nullable OriginPredicate topOriginPredicate, @Nullable byte[] tokenBindingId) {
        super(rpId, challenge);
        AssertUtil.notNull(originPredicate, "originPredicate must not be null");
        this.originPredicate = originPredicate;
        this.topOriginPredicate = topOriginPredicate;
        this.tokenBindingId = tokenBindingId;
    }

    /**
     * @param origin         origin
     * @param rpId           rpId
     * @param challenge      challenge
     * @deprecated Use {@link Builder} instead
     */
    @Deprecated
    public ServerProperty(@NotNull Origin origin, @NotNull String rpId, @Nullable Challenge challenge) {
        this(new SimpleOriginPredicate(origin), rpId, challenge, null, null);
        this.origins = Collections.singleton(origin);
    }

    /**
     * @param origins        origins
     * @param rpId           rpId
     * @param challenge      challenge
     * @deprecated Use {@link Builder} instead
     */
    @Deprecated
    public ServerProperty(@NotNull Set<Origin> origins, @NotNull String rpId, @Nullable Challenge challenge) {
        this(new SimpleOriginPredicate(origins), rpId, challenge, null, null);
        this.origins = origins;
    }

    /**
     * @param origin         origin
     * @param rpId           rpId
     * @param challenge      challenge
     * @param tokenBindingId tokenBindingId
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3. Use {@link Builder} instead
     */
    @Deprecated
    public ServerProperty(@NotNull Origin origin, @NotNull String rpId, @Nullable Challenge challenge, @Nullable byte[] tokenBindingId) {
        this(new SimpleOriginPredicate(origin), rpId, challenge, null, tokenBindingId);
        this.origins = Collections.singleton(origin);
    }

    /**
     * @param origins        origins
     * @param rpId           rpId
     * @param challenge      challenge
     * @param tokenBindingId tokenBindingId
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3. Use {@link Builder} instead
     */
    @Deprecated
    public ServerProperty(@NotNull Set<Origin> origins, @NotNull String rpId, @Nullable Challenge challenge, @Nullable byte[] tokenBindingId) {
        this(new SimpleOriginPredicate(origins), rpId, challenge, null, tokenBindingId);
        this.origins = origins;
    }

    // ~ Methods
    // ========================================================================================================


    /**
     * Returns the expected origins
     *
     * @return the origins. If originPredicate is used during the instance creation, this method returns empty.
     * @deprecated Use {@link #getOriginPredicate()} instead
     */
    @Deprecated
    public @NotNull Set<Origin> getOrigins() {
        return this.origins;
    }

    /**
     * Returns the origin predicate that validates if an origin is expected
     *
     * @return the origin predicate
     */
    public @NotNull OriginPredicate getOriginPredicate() {
        return this.originPredicate;
    }

    /**
     * Returns the top origin predicate that validates if a top origin is expected
     *
     * @return the top origin predicate
     */
    public @Nullable OriginPredicate getTopOriginPredicate() {
        return this.topOriginPredicate;
    }

    /**
     * Returns the tokenBindingId
     *
     * @return the tokenBindingId
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3.
     */
    @Deprecated(forRemoval = false)
    public @Nullable byte[] getTokenBindingId() {
        return tokenBindingId;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ServerProperty that = (ServerProperty) o;
        return Objects.equals(originPredicate, that.originPredicate) && Objects.equals(topOriginPredicate, that.topOriginPredicate) && Objects.deepEquals(tokenBindingId, that.tokenBindingId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), originPredicate, topOriginPredicate, Arrays.hashCode(tokenBindingId));
    }

    @Override
    public String toString() {
        return "ServerProperty{" +
                "originPredicate=" + originPredicate +
                ", topOriginPredicate=" + topOriginPredicate +
                ", tokenBindingId=" + Arrays.toString(tokenBindingId) +
                ", origins=" + origins +
                '}';
    }

}
