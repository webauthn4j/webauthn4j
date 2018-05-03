package net.sharplab.springframework.security.webauthn.sample.app.config;

import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

/**
 * Created by ynojima on 2017/09/16.
 */
@Configuration
public class ServerConfig implements WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> {

    @Override
    public void customize(ConfigurableServletWebServerFactory factory) {
        factory.addErrorPages(new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error/500"));
    }
}
