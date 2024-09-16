package com.spring.security.service;

import com.spring.security.entity.Usuario;
import com.spring.security.enums.Perfil;
import com.spring.security.repository.UsuarioRepository;
import com.spring.security.security.service.AutenticacaoService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UsuarioService {

    private UsuarioRepository repository;

    private AutenticacaoService autenticacaoService;

    private SecurityContextRepository securityContextRepository;

    public Usuario criarUsuario(Usuario usuario) {
        if (usuario.getPerfil() == null) {
            usuario.setPerfil(Perfil.USUARIO);
        }
        return salvarUsuario(usuario);
    }

    public Usuario editarUsuario(Usuario usuarioEditado) throws Exception {
        Usuario usuario = buscarUsuario(usuarioEditado.getId());

        if (usuarioEditado.getPerfil() == null) {
            usuarioEditado.setPerfil(usuario.getPerfil());
        }

        if (usuarioEditado.getUsuario() == null) {
            usuarioEditado.setUsuario(usuario.getUsuario());
        }

        if (usuarioEditado.getSenha() == null) {
            usuarioEditado.setSenha(usuario.getSenha());
        }

        return salvarUsuario(usuarioEditado);
    }

    private Usuario salvarUsuario(Usuario usuario) {
        return repository.save(usuario);
    }

    public Usuario buscarUsuarioLogado(Usuario usuario) {
        return usuario;
    }

    private Usuario buscarUsuario(Long id) throws Exception {
        Optional<Usuario> usuario = repository.findById(id);

        if (usuario.isEmpty()) {
            throw new Exception("Usuário não encontrado");
        }

        return usuario.get();
    }

    public List<Usuario> buscarTodosOsUsuarios() {
        return repository.findAll();
    }

    public Usuario alterarPropriaSenha(Usuario usuario, String novaSenha) throws Exception {
        if (novaSenha != null) {
            usuario.setSenha(novaSenha);
        }

        return salvarUsuario(usuario);
    }

    public void excluirUsuario(Usuario usuario, HttpServletRequest req, HttpServletResponse res) throws Exception {
        autenticacaoService.logout(securityContextRepository, req, res);
        repository.delete(usuario);
    }

}
