package com.application.authentication.configuration;

import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignInternalKeyInterceptor {

    @Bean
    public RequestInterceptor addInternalKeyHeader() {
        return template -> template.header("X-INTERNAL-KEY", "MY_SUPER_SECRET_KEY");
    }
}
