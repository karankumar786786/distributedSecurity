package one.org.security.common.model;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import one.org.security.common.dto.TokenDTO;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticatedUser implements UserDetails {

    private String id;
    private String username; // subject from token
    private String deviceHash;
    private List<String> scopes;

    public AuthenticatedUser(TokenDTO tokenDTO) {
        this.id = tokenDTO.id();
        this.username = tokenDTO.subject();
        this.deviceHash = tokenDTO.deviceHash();
        this.scopes = tokenDTO.scope();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (scopes == null)
            return List.of();
        return scopes.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return null;
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
        return true;
    }
}
