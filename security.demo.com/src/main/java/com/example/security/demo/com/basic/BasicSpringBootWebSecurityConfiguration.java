package com.example.security.demo.com.basic;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true,securedEnabled = true)
public class BasicSpringBootWebSecurityConfiguration {
	
	@Bean
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((auth) -> auth
				 .requestMatchers(new AntPathRequestMatcher("/user/**")).hasRole("USER")
	                .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")

				 .anyRequest()
				.authenticated());
http.sessionManagement(session->{
	session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
});
		//		http.formLogin();
    http.csrf().disable();		
   http.httpBasic();
   http.headers().frameOptions().sameOrigin();
		return http.build();
	}
	
//	@Bean
//	public UserDetailsService detailsService(PasswordEncoder encoder) {
//		var user=User.withUsername("durga").password(encoder.encode("1122") ).roles("USER").build();
//		var admin=User.withUsername("admin").password(encoder.encode("1122") ).roles("ADMIN").build();
//
//		return new InMemoryUserDetailsManager(user,admin);
//	}

	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource,PasswordEncoder encoder) {
		var user=User.withUsername("durga")
				.password(encoder.encode("1122") ).roles("USER").build();
		var admin=User.withUsername("admin").password(encoder.encode("1122")).roles("ADMIN").build();

	 var jdbcUserDetailsManager=new JdbcUserDetailsManager(dataSource);
	 jdbcUserDetailsManager.createUser(user);
	 jdbcUserDetailsManager.createUser(admin);
		return jdbcUserDetailsManager;
	}
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
}
