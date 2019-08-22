package com.chilecompra.springboot.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.chilecompra.springboot.app.models.entity.Usuario;

public interface IUsuarioDao extends CrudRepository<Usuario, Long>{

	public Usuario findByUsername(String username); //"select u from Usuario where u.username=u?1"
}
