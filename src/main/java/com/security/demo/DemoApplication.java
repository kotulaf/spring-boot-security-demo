package com.security.demo;

import java.util.Collections;
import java.util.Map;
import java.util.logging.Handler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class DemoApplication extends WebSecurityConfigurerAdapter {

	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal){
		return Collections.singletonMap("name", principal.getAttribute("name"));		// a map returns a key and a value, since we would get a whole object containing sensitive data from GitHub,
																						// we just return the name, which is what we wanted after all
	}
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter: off
		http
			.csrf(c -> c
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			)
			.authorizeRequests(a -> a
				.antMatchers("/", "/error", "/webjars/**").permitAll()
				.anyRequest().authenticated()
			)
			.exceptionHandling(e -> e
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
			)
			.logout(l -> l
				.logoutSuccessUrl("/").permitAll()
			)
			.oauth2Login();
			
			// @formatter: on
	}

}
