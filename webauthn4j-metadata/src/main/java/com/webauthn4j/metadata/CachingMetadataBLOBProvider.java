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

package com.webauthn4j.metadata;

import com.webauthn4j.metadata.data.MetadataBLOB;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.time.LocalDate;

public abstract class CachingMetadataBLOBProvider implements MetadataBLOBProvider {

    private MetadataBLOB cachedMetadataBLOB;
    private LocalDate cachedMetadataBLOBLastUpdate = null;
    private final Object cachedMetadataBLOBLock = new Object();

    @Override
    public @NonNull MetadataBLOB provide(){
        synchronized (cachedMetadataBLOBLock){
            if(cachedMetadataBLOB == null){
                refresh();
            }
        }
        LocalDate today = LocalDate.now();
        LocalDate nextUpdate = cachedMetadataBLOB.getPayload().getNextUpdate();
        if((nextUpdate.isBefore(today) || nextUpdate.isEqual(today)) && cachedMetadataBLOBLastUpdate.isBefore(LocalDate.now())){
            refresh();
        }

        return cachedMetadataBLOB;
    }

    public void refresh(){
        synchronized (cachedMetadataBLOBLock){
            cachedMetadataBLOB = doProvide();
            cachedMetadataBLOBLastUpdate = LocalDate.now();
        }
    }

    protected abstract @NonNull MetadataBLOB doProvide();


}
