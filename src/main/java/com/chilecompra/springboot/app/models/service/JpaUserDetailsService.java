package com.chilecompra.springboot.app.models.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.chilecompra.springboot.app.models.dao.IUsuarioDao;
import com.chilecompra.springboot.app.models.entity.Role;
import com.chilecompra.springboot.app.models.entity.Usuario;

@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService{ //para esta clase no necesito crear la interfaz, ya que la provee spring security

	@Autowired
	private IUsuarioDao usuarioDao; //inyecto el dao
	
	private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class); //para mostrar por consola
	
	@Override
	@Transactional(readOnly=true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { //cargar el usuario por su usernanme
		
        Usuario usuario = usuarioDao.findByUsername(username); //obtengo el usuario por su username
        
        if(usuario == null) {
        	logger.error("Error en el Login: no existe el usuario '" + username + "' en el sistema!");
        	throw new UsernameNotFoundException("Username: " + username + " no existe en el sistema!");
        }
        
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(); //interfaz generica de authorities
        
        for(Role role: usuario.getRoles()) { //por cada rol de los usuarios
        	logger.info("Role: ".concat(role.getAuthority()));
        	authorities.add(new SimpleGrantedAuthority(role.getAuthority())); //lo guardamos en authorities, por medio de simplegrantedauthority que implementa la interfaz
        }
        
        if(authorities.isEmpty()) {
        	logger.error("Error en el Login: Usuario '" + username + "' no tiene roles asignados!");
        	throw new UsernameNotFoundException("Error en el Login: usuario '" + username + "' no tiene roles asignados!");
        }
        
		return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
	}

}
