package org.carlspring.strongbox.configuration;

import javax.enterprise.inject.Default;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@ComponentScan({ "org.carlspring.strongbox.configuration",
                 "org.carlspring.strongbox.security",
                 "org.carlspring.strongbox.visitors" })
public class WebSecurityConfig
{

    @Bean
    @Default
    PasswordEncoder passwordEncoder()
    {
        return new StrongboxDelegatingPasswordEncoder();
    }

}
