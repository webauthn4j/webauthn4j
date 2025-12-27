package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

public class AnyOriginPredicate implements OriginPredicate {
    @Override
    public boolean test(Origin origin) {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        return true;
    }

    @Override
    public int hashCode() {
        return 31;
    }

    @Override
    public String toString() {
        return "AnyOriginPredicate{}";
    }
}
