package net.sharplab.springframework.security.webauthn.anchor;

import org.junit.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by ynojima on 2017/09/24.
 */
public class FIDOMetadataServiceTrustAnchorServiceTest {

    public FIDOMetadataServiceTrustAnchorService target = new FIDOMetadataServiceTrustAnchorService(null);

    @Test
    public void needsRefresh_test_with_cache_null(){
        target.cachedMetadataMap = null;
        assertThat(target.needsRefresh()).isTrue();
    }

    @Test
    public void needsRefresh_test_with_future_nextUpdate(){
        target.cachedMetadataMap = new HashMap<>();
        target.nextUpdate = LocalDate.now().plusDays(1);
        target.lastRefresh = LocalDateTime.now().minusWeeks(1);

        assertThat(target.needsRefresh()).isFalse();
    }

    @Test
    public void needsRefresh_test_with_equal_nextUpdate_and_lastRefresh_within_one_hour(){
        target.cachedMetadataMap = new HashMap<>();
        target.nextUpdate = LocalDate.now();
        target.lastRefresh = LocalDateTime.now().minusMinutes(59);

        assertThat(target.needsRefresh()).isFalse();
    }

    @Test
    public void needsRefresh_test_with_past_nextUpdate(){
        target.cachedMetadataMap = new HashMap<>();
        target.nextUpdate = LocalDate.now().minusDays(1);
        target.lastRefresh = LocalDateTime.now().minusWeeks(1);

        assertThat(target.needsRefresh()).isTrue();
    }



}
