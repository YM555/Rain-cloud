package com.rain.admin;


import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;


public class CustomOpaqueTokenIntrospector implements OpaqueTokenIntrospector {


	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		return null;
	}

}
