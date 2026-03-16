package com.kitchome.auth.util;

public enum Role {
    USER("USER"), ADMIN("ADMIN"), MODERATOR("MODERATOR");
    /*
    * implementing constructor for
    * projection resolution.
    **/
        private final String role;
        Role(String role){
            this.role=role;
        }
        public String getRole(){
            return role;
        }

    }


