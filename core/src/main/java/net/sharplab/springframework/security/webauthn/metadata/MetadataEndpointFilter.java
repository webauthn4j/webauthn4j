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

package net.sharplab.springframework.security.webauthn.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.exception.MetadataException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class MetadataEndpointFilter extends GenericFilterBean{

    /**
     * Default name of path suffix which will invoke this filter.
     */
    public static final String FILTER_URL = "/webauthn/metadata";

    /**
     * Url this filter should get activated on.
     */
    protected String filterProcessesUrl = FILTER_URL;

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private MetadataProvider metadataProvider;
    private AuthenticationTrustResolver trustResolver;
    private ObjectMapper objectMapper = new ObjectMapper();

    public MetadataEndpointFilter(MetadataProvider metadataProvider, AuthenticationTrustResolver trustResolver) {
        this.metadataProvider = metadataProvider;
        this.trustResolver = trustResolver;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        writeMetadata(fi.getResponse());
    }

    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        return (request.getRequestURI().contains(filterProcessesUrl));
    }

    protected void writeMetadata(HttpServletResponse response) throws IOException {
        String responseText;
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if(trustResolver.isFullyAnonymous(authentication)){
                throw new InsufficientAuthenticationException(messages.getMessage(
                        "MetadataEndpointFilter.insufficientAuthentication",
                        "Anonymous user is not allowed"));
            }
            String username = authentication.getName();
            responseText = metadataProvider.getMetadataAsString(username);
        } catch (RuntimeException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("errorMessage", e.getMessage());
            String errorResponseText;
            if(e.getClass().isAssignableFrom(InsufficientAuthenticationException.class)){
                errorResponseText = objectMapper.writeValueAsString(errorResponse);
                response.setStatus(HttpStatus.FORBIDDEN.value());
            }
            else {
                errorResponseText = objectMapper.writeValueAsString(errorResponse);
                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
            response.setContentType("application/json");
            response.getWriter().print(errorResponseText);
            return;
        }
        response.setContentType("application/json");
        response.getWriter().print(responseText);
    }

}
