package com.kitchome.auth.payload.projection;

import org.springframework.stereotype.Component;

import java.util.Set;

/*
* for propagating the user data
* across the application for authentication
* and authorisation
*
*/
public interface UserCredProjection {
    Long getId();
    String getUsername();
    String getEmail();
    String getPassword();
    Set<RolesProjection> getRoles();
    boolean isEnabled();
}
