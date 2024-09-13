package com.spring.security.entity.cenario_2;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PessoaCenarioDois {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private boolean temCachorro;

    @OneToOne(cascade = CascadeType.ALL)
    private UsuarioCenarioDois usuario;

}
