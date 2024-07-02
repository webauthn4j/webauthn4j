package com.webauthn4j.reactive.metadata;

import com.webauthn4j.metadata.data.MetadataBLOB;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

public interface MetadataBLOBReactiveProvider {

    @NotNull
    CompletionStage<MetadataBLOB> provide();

}
