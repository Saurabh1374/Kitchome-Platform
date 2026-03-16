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
public class JwtResponseDTO extends BaseDto {
    private String accessToken;
    private String refreshToken;
}
