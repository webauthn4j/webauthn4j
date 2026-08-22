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

package com.webauthn4j.async.metadata;

import com.webauthn4j.metadata.data.MetadataBLOB;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;

public abstract class CachingMetadataBLOBAsyncProvider implements MetadataBLOBAsyncProvider {

    private final Clock clock;
    // CacheState is an immutable snapshot published by replacing the reference.
    @SuppressWarnings("java:S3077")
    private volatile CacheState cache = null;
    private final AtomicReference<CompletableFuture<MetadataBLOB>> inFlight = new AtomicReference<>();

    public CachingMetadataBLOBAsyncProvider() {
        this(Clock.system(ZoneOffset.UTC));
    }

    CachingMetadataBLOBAsyncProvider(@NotNull Clock clock) {
        this.clock = clock;
    }

    @Override
    public @NotNull CompletionStage<MetadataBLOB> provide(){

        CacheState current = cache;
        if(!needsMetadataBLOBUpdate(current, clock)){
            return CompletableFuture.completedFuture(current.blob);
        }

        while(true) {
            CompletableFuture<MetadataBLOB> existing = inFlight.get();
            if (existing != null) {
                return existing;
            }

            CompletableFuture<MetadataBLOB> future = new CompletableFuture<>();
            if (inFlight.compareAndSet(null, future)) {
                CompletionStage<MetadataBLOB> stage;
                try {
                    stage = doProvide();
                }
                catch (Throwable e) {
                    inFlight.compareAndSet(future, null);
                    future.completeExceptionally(e);
                    return future;
                }
                stage.whenComplete((metadataBLOB, e) -> {
                    if (e != null) {
                        inFlight.compareAndSet(future, null);
                        future.completeExceptionally(e);
                    }
                    else {
                        cache = new CacheState(metadataBLOB, LocalDate.now(clock));
                        inFlight.compareAndSet(future, null);
                        future.complete(metadataBLOB);
                    }
                });
                return future;
            }
        }
    }

    protected abstract @NotNull CompletionStage<MetadataBLOB> doProvide();

    static boolean needsMetadataBLOBUpdate(@Nullable CacheState cache, @NotNull Clock clock){
        if(cache == null){
            return true;
        }
        LocalDate today = LocalDate.now(clock);
        LocalDate nextUpdate = cache.blob.getPayload().getNextUpdate();
        return (nextUpdate.isBefore(today) || nextUpdate.isEqual(today)) && cache.lastUpdate.isBefore(today);
    }

    static class CacheState {
        final MetadataBLOB blob;
        final LocalDate lastUpdate;

        CacheState(@NotNull MetadataBLOB blob, @NotNull LocalDate lastUpdate) {
            this.blob = blob;
            this.lastUpdate = lastUpdate;
        }
    }

}
