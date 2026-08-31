package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CachingMetadataBLOBAsyncProviderTest {

    @Test
    void nextUpdate_is_past_date_test() throws ExecutionException, InterruptedException {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        AtomicReference<Clock> clockRef = new AtomicReference<>();
        AtomicInteger callCount = new AtomicInteger(0);
        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(new DelegateClock(clockRef)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                callCount.incrementAndGet();
                return CompletableFuture.completedFuture(createMetadataBLOB(nextUpdate));
            }
        };

        clockRef.set(fixedClock(2020, Month.JANUARY, 1));
        target.provide().toCompletableFuture().get();

        clockRef.set(fixedClock(2020, Month.JANUARY, 3));
        target.provide().toCompletableFuture().get();

        assertThat(callCount.get()).isEqualTo(2);
    }

    @Test
    void nextUpdate_is_today_test() throws ExecutionException, InterruptedException {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 2);
        AtomicReference<Clock> clockRef = new AtomicReference<>();
        AtomicInteger callCount = new AtomicInteger(0);
        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(new DelegateClock(clockRef)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                callCount.incrementAndGet();
                return CompletableFuture.completedFuture(createMetadataBLOB(nextUpdate));
            }
        };

        clockRef.set(fixedClock(2020, Month.JANUARY, 1));
        target.provide().toCompletableFuture().get();

        clockRef.set(fixedClock(2020, Month.JANUARY, 2));
        target.provide().toCompletableFuture().get();

        assertThat(callCount.get()).isEqualTo(2);
    }

    @Test
    void nextUpdate_is_future_date_test() throws ExecutionException, InterruptedException {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 3);
        AtomicReference<Clock> clockRef = new AtomicReference<>();
        AtomicInteger callCount = new AtomicInteger(0);
        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(new DelegateClock(clockRef)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                callCount.incrementAndGet();
                return CompletableFuture.completedFuture(createMetadataBLOB(nextUpdate));
            }
        };

        clockRef.set(fixedClock(2020, Month.JANUARY, 1));
        target.provide().toCompletableFuture().get();

        clockRef.set(fixedClock(2020, Month.JANUARY, 2));
        target.provide().toCompletableFuture().get();

        assertThat(callCount.get()).isEqualTo(1);
    }

    @Test
    void concurrent_callers_share_same_result_test() throws Exception {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 3);
        MetadataBLOB blob = createMetadataBLOB(nextUpdate);
        CompletableFuture<MetadataBLOB> pendingFuture = new CompletableFuture<>();
        AtomicInteger callCount = new AtomicInteger(0);

        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(fixedClock(2020, Month.JANUARY, 1)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                callCount.incrementAndGet();
                return pendingFuture;
            }
        };

        CompletionStage<MetadataBLOB> result1 = target.provide();
        CompletionStage<MetadataBLOB> result2 = target.provide();
        CompletionStage<MetadataBLOB> result3 = target.provide();

        pendingFuture.complete(blob);

        assertThat(result1.toCompletableFuture().get(1, TimeUnit.SECONDS)).isSameAs(blob);
        assertThat(result2.toCompletableFuture().get(1, TimeUnit.SECONDS)).isSameAs(blob);
        assertThat(result3.toCompletableFuture().get(1, TimeUnit.SECONDS)).isSameAs(blob);
        assertThat(callCount.get()).isEqualTo(1);
    }

    @Test
    void retry_after_async_failure_test() throws Exception {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 3);
        MetadataBLOB blob = createMetadataBLOB(nextUpdate);
        CompletableFuture<MetadataBLOB> failingFuture = new CompletableFuture<>();
        failingFuture.completeExceptionally(new RuntimeException("network error"));

        AtomicInteger callCount = new AtomicInteger(0);
        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(fixedClock(2020, Month.JANUARY, 1)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                if (callCount.incrementAndGet() == 1) {
                    return failingFuture;
                }
                return CompletableFuture.completedFuture(blob);
            }
        };

        CompletionStage<MetadataBLOB> firstResult = target.provide();
        assertThatThrownBy(() -> firstResult.toCompletableFuture().get(1, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(RuntimeException.class);

        CompletionStage<MetadataBLOB> secondResult = target.provide();
        assertThat(secondResult.toCompletableFuture().get(1, TimeUnit.SECONDS)).isSameAs(blob);
        assertThat(callCount.get()).isEqualTo(2);
    }

    @Test
    void retry_after_sync_exception_test() throws Exception {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 3);
        MetadataBLOB blob = createMetadataBLOB(nextUpdate);

        AtomicInteger callCount = new AtomicInteger(0);
        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(fixedClock(2020, Month.JANUARY, 1)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                if (callCount.incrementAndGet() == 1) {
                    throw new RuntimeException("sync error");
                }
                return CompletableFuture.completedFuture(blob);
            }
        };

        CompletionStage<MetadataBLOB> firstResult = target.provide();
        assertThatThrownBy(() -> firstResult.toCompletableFuture().get(1, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(RuntimeException.class);

        CompletionStage<MetadataBLOB> secondResult = target.provide();
        assertThat(secondResult.toCompletableFuture().get(1, TimeUnit.SECONDS)).isSameAs(blob);
        assertThat(callCount.get()).isEqualTo(2);
    }


    @Test
    void retry_from_failure_callback_test() throws Exception {
        LocalDate nextUpdate = LocalDate.of(2020, Month.JANUARY, 3);
        MetadataBLOB blob = createMetadataBLOB(nextUpdate);

        AtomicInteger callCount = new AtomicInteger(0);
        CachingMetadataBLOBAsyncProvider target = new CachingMetadataBLOBAsyncProvider(fixedClock(2020, Month.JANUARY, 1)) {
            @Override
            protected @NotNull CompletionStage<MetadataBLOB> doProvide() {
                if (callCount.incrementAndGet() == 1) {
                    return CompletableFuture.failedFuture(new RuntimeException("first attempt"));
                }
                return CompletableFuture.completedFuture(blob);
            }
        };

        MetadataBLOB result = target.provide()
                .exceptionallyCompose(e -> target.provide())
                .toCompletableFuture()
                .get(1, TimeUnit.SECONDS);

        assertThat(result).isSameAs(blob);
        assertThat(callCount).hasValue(2);
    }


    private static Clock fixedClock(int year, Month month, int day) {
        LocalDate date = LocalDate.of(year, month, day);
        return Clock.fixed(date.atStartOfDay(ZoneOffset.UTC).toInstant(), ZoneOffset.UTC);
    }

    private MetadataBLOB createMetadataBLOB(LocalDate nextUpdate){
        JWSFactory factory = new JWSFactory(new ObjectConverter());
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, null);
        MetadataBLOBPayload payload = new MetadataBLOBPayload("", 0, nextUpdate, Collections.emptyList());
        JWS<MetadataBLOBPayload> jws = factory.create(header, payload, new byte[32]);
        return new MetadataBLOB(jws);
    }

    private static class DelegateClock extends Clock {
        private final AtomicReference<Clock> delegate;

        DelegateClock(AtomicReference<Clock> delegate) {
            this.delegate = delegate;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return delegate.get().instant();
        }
    }

}
