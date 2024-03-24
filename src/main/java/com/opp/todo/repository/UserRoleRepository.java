package com.opp.todo.repository;

import com.opp.todo.model.AppUserRole;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRoleRepository extends CrudRepository<AppUserRole,Long> {
    Optional<AppUserRole> findByRole(String role);
}
