package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

public class SimpleOriginPredicate implements OriginPredicate {

    private final Set<Origin> origins;

    SimpleOriginPredicate(Set<Origin> origins) {
        this.origins = origins;
    }

    SimpleOriginPredicate(Origin origin) {
        this.origins = Collections.singleton(origin);
    }

    @Override
    public boolean test(Origin origin) {
        return origins.contains(origin);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SimpleOriginPredicate that = (SimpleOriginPredicate) o;
        return Objects.equals(origins, that.origins);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(origins);
    }

    @Override
    public String toString() {
        return "SimpleOriginPredicate{" +
                "origins=" + origins +
                '}';
    }
}
