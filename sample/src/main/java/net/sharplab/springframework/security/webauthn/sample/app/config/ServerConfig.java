package net.sharplab.springframework.security.webauthn.sample.app.config;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

/**
 * Created by ynojima on 2017/09/16.
 */
@Configuration
public class ServerConfig extends ServerProperties {

    @Override
    public void customize(ConfigurableEmbeddedServletContainer container){

        super.customize(container);
        container.addErrorPages(new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error/500"));

    }
}
