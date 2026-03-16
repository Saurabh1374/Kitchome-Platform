package com.kitchome.auth.service;

import com.kitchome.auth.payload.RegisterUserDTO;

public interface UserService {
	public Boolean registerUser(RegisterUserDTO userdto); 

}
