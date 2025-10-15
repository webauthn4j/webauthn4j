package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

import java.util.function.Predicate;

public interface OriginPredicate extends Predicate<Origin> {
}
