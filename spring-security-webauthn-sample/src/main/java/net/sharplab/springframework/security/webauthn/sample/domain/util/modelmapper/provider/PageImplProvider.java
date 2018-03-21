package net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.provider;

import org.modelmapper.Provider;
import org.springframework.data.domain.PageImpl;

import java.util.Collections;

/**
 * PageImplのインスタンスプロバイダ。
 */
public class PageImplProvider implements Provider<PageImpl> {

    @Override
    public PageImpl get(ProvisionRequest<PageImpl> request) {
        //noinspection unchecked
        return new PageImpl(Collections.emptyList());
    }
}
