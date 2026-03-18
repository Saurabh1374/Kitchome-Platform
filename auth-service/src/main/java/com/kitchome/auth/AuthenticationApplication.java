package com.kitchome.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;



import org.springframework.cloud.vault.config.VaultAutoConfiguration;
import org.springframework.cloud.vault.config.VaultReactiveAutoConfiguration;

@SpringBootApplication(exclude = {VaultAutoConfiguration.class, VaultReactiveAutoConfiguration.class})
public class AuthenticationApplication extends SpringBootServletInitializer{

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}
	
	@Override
	 protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
	        return builder.sources(AuthenticationApplication.class);
	    }


}
