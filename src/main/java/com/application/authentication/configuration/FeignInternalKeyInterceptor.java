package com.application.authentication.configuration;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignInternalKeyInterceptor {

    // Read from config, never inlined: a key hardcoded in source is published
    // to everyone who can read the repository.
    @Value("${internal.role-service-key}")
    private String internalKey;

    @Bean
    public RequestInterceptor addInternalKeyHeader() {
        return template -> template.header("X-INTERNAL-KEY", internalKey);
    }
}
