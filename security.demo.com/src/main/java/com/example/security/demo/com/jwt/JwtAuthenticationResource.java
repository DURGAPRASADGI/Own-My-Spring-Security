package com.example.security.demo.com.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController

public class JwtAuthenticationResource {
	@Autowired
	private JwtEncoder jwtencoder;

	


   public JwtAuthenticationResource(JwtEncoder jwtencoder) {
		super();
		this.jwtencoder = jwtencoder;
	}


	
	@PostMapping("/authenticate")
	public JwtRespose authenticate(Authentication authentication) {
		return new JwtRespose(createToken(authentication));
		
	}
	   private String createToken(Authentication authentication) {
		// TODO Auto-generated method stub
		  var clam= JwtClaimsSet.builder().issuer("self").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60*30)).subject(authentication.getName()).claim("scope", createScope(authentication)).build();
		return jwtencoder.encode(JwtEncoderParameters.from(clam)).getTokenValue();
	}
	private String createScope(Authentication authentication) {
		// TODO Auto-generated method stub
		return authentication.getAuthorities().stream().map(a->a.getAuthority()).collect(Collectors.joining(""));
	}
	record JwtRespose(String Token) {
	   }	   
		   


}
