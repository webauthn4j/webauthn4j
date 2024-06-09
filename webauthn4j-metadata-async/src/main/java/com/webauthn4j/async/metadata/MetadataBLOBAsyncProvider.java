package com.webauthn4j.async.metadata;

import com.webauthn4j.metadata.data.MetadataBLOB;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

public interface MetadataBLOBAsyncProvider {

    @NotNull
    CompletionStage<MetadataBLOB> provide();

}
