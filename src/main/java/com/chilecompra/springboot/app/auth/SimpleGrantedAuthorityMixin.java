package com.chilecompra.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityMixin {
	
	@JsonCreator //constructor por defecto para los objetos authorities a partir del json, mapear el json como atributo rol
	public SimpleGrantedAuthorityMixin(@JsonProperty("authority") String role) {}

}
