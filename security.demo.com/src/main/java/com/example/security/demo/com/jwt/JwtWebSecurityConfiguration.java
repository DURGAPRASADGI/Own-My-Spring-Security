package com.example.security.demo.com.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//@Configuration
public class JwtWebSecurityConfiguration {
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((auth) -> auth.anyRequest().authenticated());
http.sessionManagement(session->{
	session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
});
		//		http.formLogin();
    http.csrf().disable();		
   http.httpBasic();
   http.headers().frameOptions().sameOrigin();
   http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		return http.build();
	}
	

	
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

	@Bean
	public KeyPair keyPair() throws NoSuchAlgorithmException {
		var keypairGeneartor=KeyPairGenerator.getInstance("RSA");
		keypairGeneartor.initialize(2048);
		return keypairGeneartor.generateKeyPair();
	}
	
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey(keyPair.getPrivate()).keyID(UUID.randomUUID().toString()).build();
	}
	
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwtSet=new JWKSet();
		return (jWKSelector,context)->jWKSelector.select(jwtSet);
//		new JWKSource() {
//
//			@Override
//			public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//				// TODO Auto-generated method stub
//				return jwkSelector.select(jwtSet);
//			}
//		};
//		return null;
	}
	
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
	}
	
	@Bean
	public JwtEncoder jwtEncoder( JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}
