package com.chilecompra.springboot.app.view.csv;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.AbstractView;
import org.supercsv.io.CsvBeanWriter;
import org.supercsv.io.ICsvBeanWriter;
import org.supercsv.prefs.CsvPreference;

import com.chilecompra.springboot.app.models.entity.Cliente;

@Component("listar.csv") //asociado a una vista en el controlador
public class ClienteCsvView extends AbstractView {

	public ClienteCsvView() {
		setContentType("text/csv");
	}

	@Override
	protected boolean generatesDownloadContent() {
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		response.setHeader("Content-Disposition", "attachment; filename=\"clientes.csv\""); //nombre del archivo
		response.setContentType(getContentType()); //le pasamos el contenido a la respuesta

		Page<Cliente> clientes = (Page<Cliente>) model.get("clientes");
		//List<Cliente> clientes = (List<Cliente>) model.get("clientes");
		
		ICsvBeanWriter beanWriter = new CsvBeanWriter(response.getWriter(),  CsvPreference.STANDARD_PREFERENCE); //lo guardamos en la respuesta
		
		String[] header = {"id", "nombre", "apellido", "email", "createAt"}; //tienen que llamarse igual a los atributos del entity
		beanWriter.writeHeader(header);
		
		for(Cliente cliente: clientes) {
			beanWriter.write(cliente, header); //lo guardamos en el archivo plano y pasamos el objeto cliente con los nombres de columna
		}
		
		beanWriter.close();
	}

}
