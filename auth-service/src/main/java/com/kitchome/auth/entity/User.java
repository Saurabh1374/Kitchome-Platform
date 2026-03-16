package com.kitchome.auth.entity;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.kitchome.auth.util.Role;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import lombok.EqualsAndHashCode;
import com.kitchome.common.base.BaseEntity;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Data
@EqualsAndHashCode(callSuper = false)
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String email;
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<Role> roles = new HashSet<>();;
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<RefreshToken> sessions;

    @Column(name = "enabled")
    private boolean enabled = false;

    @Column(name = "password_last_updated")
    private java.time.LocalDateTime passwordLastUpdated;

    @Column(name = "provider")
    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    // Getters and Setters
    @JsonProperty("roles")
    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void setRoles(Role role) {
        this.roles.add(role);
    }
}
