package com.spring.security.service;

import com.spring.security.entity.Usuario;
import com.spring.security.enums.Perfil;
import com.spring.security.repository.UsuarioRepository;
import com.spring.security.security.service.AutenticacaoService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UsuarioService {

    private UsuarioRepository repository;

    private AutenticacaoService autenticacaoService;

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

        if (usuarioEditado.getNome() == null) {
            usuarioEditado.setNome(usuario.getNome());
        }

        if (usuarioEditado.getEmail() == null) {
            usuarioEditado.setEmail(usuario.getEmail());
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

    public void excluirUsuario(Usuario usuario, HttpServletResponse response) throws Exception {
        autenticacaoService.logout(response);
        repository.delete(usuario);
    }
}
