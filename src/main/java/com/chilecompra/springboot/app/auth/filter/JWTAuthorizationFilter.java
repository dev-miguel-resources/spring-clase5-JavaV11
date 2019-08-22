package com.chilecompra.springboot.app.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.chilecompra.springboot.app.auth.service.JWTService;
//import com.chilecompra.springboot.app.auth.service.JWTService;
import com.chilecompra.springboot.app.auth.service.JWTServiceImpl;


public class JWTAuthorizationFilter extends BasicAuthenticationFilter { //verifica la autorización de los request
	
	private JWTService jwtService; 

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService; //inicializamos el atributo de la clase
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader(JWTServiceImpl.HEADER_STRING);

		if (!requiresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = null; //se define
		
		if(jwtService.validate(header)) { //si esta validado
			authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null, jwtService.getRoles(header));
		}
		
		SecurityContextHolder.getContext().setAuthentication(authentication); //pasamos el objeto autenticado bajo el contexto de seguridad
		chain.doFilter(request, response); //pasamos el request y el response
		
	}

	protected boolean requiresAuthentication(String header) {

		if (header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
			return false;
		}
		return true;
	}

}
