package com.application.authentication.repository;

import com.application.authentication.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, String> {

    Optional<Users> findByUsername(String username);

//    Optional<Users> findUserByUsernameAndOriginalPassword(String username, String password);

    Optional<Users> findByEmail(String email);

    String username(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

//    boolean existsByEmail(String email);
//
//    boolean existsByUsername(String email);

//    User findByEmail(String email);

//    User findAddressByUserId(String userId);

}
