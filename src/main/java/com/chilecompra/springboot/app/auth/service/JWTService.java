package com.chilecompra.springboot.app.auth.service;

import java.io.IOException;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;

public interface JWTService { //provee un diseño generico para cualquier implementación con jwt con buenas practicas

	public String create(Authentication auth) throws IOException;
	public boolean validate(String token); //para validar recibiendo el token
	public Claims getClaims(String token); //el token para obtener los claims o datos o payload, es lo mismo
	public String getUsername(String token); //obtener el username desde el token en json
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException; //obtener los roles desde el token en json
	public String resolve(String token); //entrega el codigo del token
}
