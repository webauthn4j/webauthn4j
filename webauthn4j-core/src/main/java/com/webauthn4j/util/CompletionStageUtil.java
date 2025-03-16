package com.webauthn4j.util;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

public class CompletionStageUtil {

    public static <U> CompletionStage<U> supply(Supplier<U> supplier) {
        try{
            U result = supplier.get();
            return CompletableFuture.completedFuture(result);
        }
        catch (RuntimeException e){
            return CompletableFuture.failedStage(e);
        }
    }

    public static <U> CompletionStage<U> compose(Supplier<CompletionStage<U>> supplier) {
        try{
            return supplier.get();
        }
        catch (RuntimeException e){
            return CompletableFuture.failedStage(e);
        }
    }


}
