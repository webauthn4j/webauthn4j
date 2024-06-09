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

import java.time.LocalDate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class CachingMetadataBLOBAsyncProvider implements MetadataBLOBAsyncProvider {

    private MetadataBLOB cachedMetadataBLOB = null;
    private CompletableFuture<MetadataBLOB> metadataBLOBFuture = new CompletableFuture<>();
    private LocalDate metadataBLOBLastUpdate = null;
    private final Object metadataBLOBFutureLock = new Object();
    private final Lock metadataBLOBRefreshingLock = new ReentrantLock();

    @Override
    public @NotNull CompletionStage<MetadataBLOB> provide(){

        if(!needsMetadataBLOBUpdate(cachedMetadataBLOB, metadataBLOBLastUpdate)){
            return CompletableFuture.completedFuture(cachedMetadataBLOB);
        }

        CompletableFuture<MetadataBLOB> response;
        synchronized (metadataBLOBFutureLock){
            response = metadataBLOBFuture;
        }

        if(metadataBLOBRefreshingLock.tryLock()){
            doProvide()
                    .thenAccept(metadataBLOB -> {
                        cachedMetadataBLOB = metadataBLOB;
                        metadataBLOBLastUpdate = LocalDate.now();
                        synchronized (metadataBLOBFutureLock){
                            metadataBLOBFuture.complete(metadataBLOB);
                            metadataBLOBFuture = new CompletableFuture<>();
                        }
                    })
                    .exceptionally(e ->{
                        synchronized (metadataBLOBFutureLock){
                            metadataBLOBFuture.completeExceptionally(e);
                            metadataBLOBFuture = new CompletableFuture<>();
                        }
                        metadataBLOBRefreshingLock.unlock();
                        return null;
                    });
        }
        return response;
    }

    protected abstract @NotNull CompletionStage<MetadataBLOB> doProvide();

    static boolean needsMetadataBLOBUpdate(MetadataBLOB cachedMetadataBLOB, LocalDate metadataBLOBLastUpdate){
        if(cachedMetadataBLOB == null){
            return true;
        }
        LocalDate today = LocalDate.now();
        LocalDate nextUpdate = cachedMetadataBLOB.getPayload().getNextUpdate();
        return (nextUpdate.isBefore(today) || nextUpdate.isEqual(today)) && metadataBLOBLastUpdate.isBefore(today);
    }

}
