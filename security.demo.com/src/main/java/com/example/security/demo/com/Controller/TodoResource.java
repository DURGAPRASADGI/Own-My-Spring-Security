package com.example.security.demo.com.Controller;


import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoResource {
	Logger logger=LoggerFactory.getLogger(getClass());
	
	private static final List<Todo> Todo_List = List.of(new Todo("in28Minutes", "Learn Aws")
			,new Todo("in28Minutes", "Get Aws Cerificate"));

	@GetMapping("/todos")
	public List<Todo> retriveAllTodos()
	{
		
		return Todo_List;
	}
	
	@GetMapping("/user/{userName}/todos")
	@PreAuthorize("hasRole('USER') ")
	@PostAuthorize("returnObject.userName=='in28Minutes'")
	@RolesAllowed({"ADMIN","USER"})
	@Secured({"ROLE_ADMIN","ROLE_USER"})
	public Todo reteriviewForSpecificTodo(@PathVariable String userName){
		return Todo_List.get(0);
		
	}
	
	@PostMapping("/user/{userName}/todos")
	public void CreateForSpecificTodo(@PathVariable String userName){
		logger.info(userName);
		
	}
	record Todo (String userName,String description) {
		
	}
}
