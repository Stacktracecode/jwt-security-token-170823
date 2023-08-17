package com.impds.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.impds.config.JwtUtil;
import com.impds.model.JwtRequest;
import com.impds.model.JwtResponse;
import com.impds.service.JwtUserDetailsService;

@RestController
public class JwtController {

	private final AuthenticationManager authenticationManager;
	private final JwtUtil jwtUtil;
	private final JwtUserDetailsService jwtUserDetailsService;

	@Autowired
	public JwtController(AuthenticationManager authenticationManager, JwtUtil jwtUtil,
			JwtUserDetailsService jwtUserDetailsService) {
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.jwtUserDetailsService = jwtUserDetailsService;
	}

	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest)
			throws AuthenticationException {

		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
				authenticationRequest.getPassword()));

		final UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		final String jwt = jwtUtil.generateToken(userDetails);

		return ResponseEntity.ok(new JwtResponse(jwt));
	}

	@GetMapping("/secure")
	public ResponseEntity<String> secureEndpoint() {
		String message = "You have accessed the secure endpoint!";
		return ResponseEntity.ok(message);
	}
}
