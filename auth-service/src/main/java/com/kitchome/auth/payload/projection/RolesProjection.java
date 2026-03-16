package com.kitchome.auth.payload.projection;

import com.kitchome.auth.util.Role;
import org.springframework.stereotype.Component;

/*
*mapping relations in the table
* role------1:n------>users
*/
@Component
public interface RolesProjection {
    Role getRole();
}
