package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.LocalDate;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.mockito.Mockito.*;

class CachingMetadataBLOBAsyncProviderTest {

    @Test
    void nextUpdate_is_past_date_test() throws ExecutionException, InterruptedException {
        LocalDate nextUpdate = LocalDate.of(2020, 1, 2);
        CachingMetadataBLOBAsyncProvider target = spy(CachingMetadataBLOBAsyncProvider.class);
        when(target.doProvide()).thenReturn(CompletableFuture.completedFuture(createMetadataBLOB(nextUpdate)));
        LocalDate firstTrialDay = LocalDate.of(2020, 1, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, 1, 3);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(LocalDate::now).thenReturn(firstTrialDay);
            target.provide().toCompletableFuture().get();
            mock.when(LocalDate::now).thenReturn(secondTrialDay);
            target.provide().toCompletableFuture().get();
            verify(target, times(2)).doProvide();
        }
    }

    @Test
    void nextUpdate_is_today_test(){
        LocalDate nextUpdate = LocalDate.of(2020, 1, 2);
        CachingMetadataBLOBAsyncProvider target = spy(CachingMetadataBLOBAsyncProvider.class);
        when(target.doProvide()).thenReturn(CompletableFuture.completedFuture(createMetadataBLOB(nextUpdate)));
        LocalDate firstTrialDay = LocalDate.of(2020, 1, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, 1, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(LocalDate::now).thenReturn(firstTrialDay);
            target.provide();
            mock.when(LocalDate::now).thenReturn(secondTrialDay);
            target.provide();
            verify(target, times(2)).doProvide();
        }
    }

    @Test
    void nextUpdate_is_future_date_test(){
        LocalDate nextUpdate = LocalDate.of(2020, 1, 3);
        CachingMetadataBLOBAsyncProvider target = spy(CachingMetadataBLOBAsyncProvider.class);
        when(target.doProvide()).thenReturn(CompletableFuture.completedFuture(createMetadataBLOB(nextUpdate)));
        LocalDate firstTrialDay = LocalDate.of(2020, 1, 1);
        LocalDate secondTrialDay = LocalDate.of(2020, 1, 2);
        try(MockedStatic<LocalDate> mock = Mockito.mockStatic(LocalDate.class)){
            mock.when(LocalDate::now).thenReturn(firstTrialDay);
            target.provide();
            mock.when(LocalDate::now).thenReturn(secondTrialDay);
            target.provide();
            verify(target, times(1)).doProvide();
        }
    }



    private MetadataBLOB createMetadataBLOB(LocalDate nextUpdate){
        JWSFactory factory = new JWSFactory(new ObjectConverter());
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, null);
        MetadataBLOBPayload payload = new MetadataBLOBPayload("", 0, nextUpdate, Collections.emptyList());
        JWS<MetadataBLOBPayload> jws = factory.create(header, payload, new byte[32]);
        return new MetadataBLOB(jws);
    }

}