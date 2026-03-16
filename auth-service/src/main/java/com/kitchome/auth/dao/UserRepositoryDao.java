package com.kitchome.auth.dao;

import java.util.Optional;

import com.kitchome.auth.payload.projection.UserCredProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.kitchome.auth.entity.User;

@Repository
public interface UserRepositoryDao extends JpaRepository<User, Long> {
	Boolean existsByEmail(String email);

	Optional<UserCredProjection> findByEmailIgnoreCase(String email);

	Optional<UserCredProjection> findByUsernameIgnoreCase(String username);

	Optional<User> findByUsername(String username);

	Optional<User> findUserByEmailIgnoreCase(String email);
}
