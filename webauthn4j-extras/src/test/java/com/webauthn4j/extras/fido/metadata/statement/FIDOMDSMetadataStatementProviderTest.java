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

package com.webauthn4j.extras.fido.metadata.statement;

import com.webauthn4j.extras.fido.metadata.SimpleFIDOMDSClient;
import com.webauthn4j.registry.Registry;
import org.junit.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class FIDOMDSMetadataStatementProviderTest {

    private FIDOMDSMetadataStatementProvider target = new FIDOMDSMetadataStatementProvider(new Registry(), new SimpleFIDOMDSClient());
    private OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);

    @Test
    public void needsRefresh_test_with_cache_null() {
        target.cachedMetadataMap = null;
        assertThat(target.needsRefresh()).isTrue();
    }

    @Test
    public void needsRefresh_test_with_future_nextUpdate() {
        target.cachedMetadataMap = new HashMap<>();
        target.nextUpdate = now.plusDays(1);
        target.lastRefresh = now.minusWeeks(1);

        assertThat(target.needsRefresh()).isFalse();
    }

    @Test
    public void needsRefresh_test_with_equal_nextUpdate_and_lastRefresh_within_one_hour() {
        target.cachedMetadataMap = new HashMap<>();
        target.nextUpdate = now;
        target.lastRefresh = now.minusMinutes(59);

        assertThat(target.needsRefresh()).isFalse();
    }

    @Test
    public void needsRefresh_test_with_past_nextUpdate() {
        target.cachedMetadataMap = new HashMap<>();
        target.nextUpdate = now.minusDays(1);
        target.lastRefresh = now.minusWeeks(1);

        assertThat(target.needsRefresh()).isTrue();
    }
}
