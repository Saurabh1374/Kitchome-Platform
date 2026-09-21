package com.kitchome.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration
public class RagPostgresConfig {

    @Value("${rag.datasource.url:jdbc:postgresql://192.168.0.117:5432/rag_pg}")
    private String ragUrl;

    @Value("${rag.datasource.username:postgres}")
    private String ragUsername;

    @Value("${rag.datasource.password:Sameer7277}")
    private String ragPassword;

    @Value("${rag.datasource.driver-class-name:org.postgresql.Driver}")
    private String ragDriverClassName;

    @Bean(name = "ragJdbcTemplate")
    public JdbcTemplate ragJdbcTemplate() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(ragDriverClassName);
        dataSource.setUrl(ragUrl);
        dataSource.setUsername(ragUsername);
        dataSource.setPassword(ragPassword);
        return new JdbcTemplate(dataSource);
    }
}
