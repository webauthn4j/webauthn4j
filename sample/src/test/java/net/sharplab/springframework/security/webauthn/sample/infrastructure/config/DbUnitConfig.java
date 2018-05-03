package net.sharplab.springframework.security.webauthn.sample.infrastructure.config;

import org.dbunit.database.DatabaseDataSourceConnection;
import org.dbunit.database.IDatabaseConnection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.sql.SQLException;

/**
 * DbUnitConfig for testing
 */

@Configuration
public class DbUnitConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    public IDatabaseConnection dbUnitDatabaseConnection () throws SQLException {
        return new DatabaseDataSourceConnection(dataSource);
    }


}
