package com.spring.security.controller;

import com.spring.security.entity.Usuario;
import com.spring.security.service.UsuarioService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/usuarios")
public class UsuarioController {

    private UsuarioService service;

    @PreAuthorize("hasAuthority('ADMINISTRADOR')")
    @PostMapping
    public ResponseEntity<?> criarUsuario(@Valid @RequestBody Usuario usuario) {
        try {
            return new ResponseEntity<>(service.criarUsuario(usuario), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PreAuthorize("hasAuthority('FUNCIONARIO')")
    @PutMapping
    public ResponseEntity<?> editarUsuario(@Valid @RequestBody Usuario usuarioEditado) {
        try {
            return new ResponseEntity<>(service.editarUsuario(usuarioEditado), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PreAuthorize("hasAuthority('USUARIO')")
    @GetMapping("/detalhes")
    public ResponseEntity<?> buscarUsuario(@AuthenticationPrincipal Usuario usuario) {
        try {
            return new ResponseEntity<>(service.buscarUsuarioLogado(usuario), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PreAuthorize("permitAll()")
    @GetMapping
    public ResponseEntity<?> buscarTodosOsUsuarios() {
        try {
            return new ResponseEntity<>(service.buscarTodosOsUsuarios(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PreAuthorize("isAuthenticated()")
    @PatchMapping("/senha")
    public ResponseEntity<?> alterarPropriaSenha(@AuthenticationPrincipal Usuario usuario,
                                                 @RequestBody Usuario usuarioAtualizado) {
        try {
            return new ResponseEntity<>(service.alterarPropriaSenha(usuario, usuarioAtualizado.getSenha()), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping
    public ResponseEntity<?> excluirUsuario(@AuthenticationPrincipal Usuario usuario, HttpServletRequest req,
                                            HttpServletResponse res) {
        try {
            service.excluirUsuario(usuario, req, res);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

}
