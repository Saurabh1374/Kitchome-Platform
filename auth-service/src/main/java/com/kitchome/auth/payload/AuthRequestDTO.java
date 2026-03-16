package com.kitchome.auth.payload;

import com.kitchome.common.base.BaseDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class AuthRequestDTO extends BaseDto {
    private String username;
    private String password;
}
