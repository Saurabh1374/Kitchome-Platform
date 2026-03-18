package com.kitchome.auth.authentication;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.kitchome.auth.payload.projection.UserCredProjection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class CustomUserDetails implements UserDetails, OAuth2User {
	/**
	 * implemented equals and hashcode
	 * for session registry and concurrent
	 * session control.
	 */
	private static final long serialVersionUID = 1L;
	private final Long id;
	private final String userName;
	private final String email;
	private final String password;
	private final Collection<GrantedAuthority> authorities;
	private final boolean enabled;
	private final boolean emailVerified;
	private final Map<String, Object> attributes;

	public CustomUserDetails(UserCredProjection user) {
		super();
		this.id = user.getId();
		this.userName = user.getUsername();
		this.email = user.getEmail();
		this.password = user.getPassword();

		Set<GrantedAuthority> auths = user.getRoles().stream()
				.map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role.getRole()))
				.collect(Collectors.toSet());

		// Ensure ROLE_USER is present if no roles are assigned
		if (auths.isEmpty()) {
			auths.add(new SimpleGrantedAuthority("ROLE_USER"));
		}

		this.authorities = auths;
		this.enabled = user.isEnabled();
		this.emailVerified = user.isEmailVerified();
		this.attributes = null;
	}

	public CustomUserDetails(Long id, String username, String email, Collection<GrantedAuthority> authorities,
			Map<String, Object> attributes) {
		this.id = id;
		this.userName = username;
		this.email = email;
		this.password = null; // Social login

		// Ensure ROLE_USER is present if no authorities are provided
		if (authorities == null || authorities.isEmpty()) {
			this.authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));
		} else {
			this.authorities = authorities;
		}

		this.enabled = true;
		this.emailVerified = true;
		this.attributes = attributes;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public <A> A getAttribute(String name) {
		return attributes == null ? null : (A) attributes.get(name);
	}

	@Override
	public String getName() {
		return userName;
	}

	public Long getId() {
		return id;
	}

	public String getEmail() {
		return email;
	}

	public boolean isEmailVerified() {
		return emailVerified;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CustomUserDetails other = (CustomUserDetails) obj;
		if (userName == null) {
			if (other.userName != null)
				return false;
		} else if (!userName.equals(other.userName)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((userName == null) ? 0 : userName.hashCode());
		return result;
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getPassword() {
		return this.password;
	}

	@Override
	public String getUsername() {
		return this.userName;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return this.enabled;
	}

}
