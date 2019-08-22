package com.chilecompra.springboot.app.auth.filter;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.chilecompra.springboot.app.auth.service.JWTService;
import com.chilecompra.springboot.app.auth.service.JWTServiceImpl;
import com.chilecompra.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;


public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter { //autenticar usando credenciales

	private AuthenticationManager authenticationManager; //componente encargado de la autenticación por debajo con jpauserdetail
	private JWTService jwtService;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST")); //si la ruta es diferente de esta no se lleva a cabo el filtro
		
		this.jwtService = jwtService; //lo inicializamos
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException { //metodo intentar autenticar
		
		String username = obtainUsername(request);
		String password = obtainPassword(request);
		
		if(username != null && password !=null) {
			logger.info("Username desde request parameter (form-data): " + username);
			logger.info("Password desde request parameter (form-data): " + password);
			
		} else {
			Usuario user = null;
			try {
				
				user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class); //convertimos un json a objeto
				
				username = user.getUsername();
				password = user.getPassword();
				
				logger.info("Username desde request InputStream (raw): " + username); //para leer los datos en bruto
				logger.info("Password desde request InputStream (raw): " + password);
				
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		username = username.trim();
		
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password); //token a nivel de servidor, obtiene las credenciales
		
		return authenticationManager.authenticate(authToken); //se envia el token interno para formar el jwt
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException { //aca el auth ya esta autenticado

		String token = jwtService.create(authResult);
		
		response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX + token);
		
		Map<String, Object> body = new HashMap<String, Object>(); //vamos a pasar varios datos
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito!", ((User)authResult.getPrincipal()).getUsername()) );
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body)); //escritor de la respuesta
		response.setStatus(200); //200 OK
		response.setContentType("application/json"); //en que formato lo retorna
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException { //maneja la falla del login cuando falla

		Map<String, Object> body = new HashMap<String, Object>();
		body.put("mensaje", "Error de autenticación: username o password incorrecto!");
		body.put("error", failed.getMessage());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);
		response.setContentType("application/json");
	}
	
	

}
