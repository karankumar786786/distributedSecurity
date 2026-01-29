package one.org.security.Autherization.core.domain.entity;

import java.util.Collection;
import java.util.Collections;

import org.bson.types.ObjectId;
import org.springframework.security.core.GrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import org.springframework.security.core.userdetails.UserDetails;

@Builder
@Data
@AllArgsConstructor
public class UserMockEntity implements UserDetails {
    private static final long serialVersionUID = 1L;
    private ObjectId id;
    private String username;
    private String password; // Added to satisfy UserDetails

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections
                .singleton(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
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
