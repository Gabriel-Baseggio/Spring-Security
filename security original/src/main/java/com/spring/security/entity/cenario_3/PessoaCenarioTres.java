package com.spring.security.entity.cenario_3;

import com.spring.security.entity.cenario_2.UsuarioCenarioDois;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PessoaCenarioTres {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private boolean temCachorro;

    private String usuario;

    private String email;

    private String senha;

    private String perfil;

}
