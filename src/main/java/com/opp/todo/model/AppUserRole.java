package com.opp.todo.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class AppUserRole extends LogEntity{

    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String role;

    public AppUserRole() {
    }

    public AppUserRole(String role) {
        this.role = role;
    }
}
