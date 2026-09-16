package com.kitchome.auth.payload;

import com.kitchome.auth.entity.AccessPromotionRequest;
import com.kitchome.auth.entity.UserServiceAccessOverview;
import com.kitchome.common.base.BaseDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode(callSuper = false)
public class UnifiedProfileResponseDTO extends BaseDto {
    private String username;
    private String email;
    private String roles;
    private String tier;
    private String tenantId;
    private String organizationName;
    private List<UserServiceAccessOverview> serviceAccess;
    private List<AccessPromotionRequest> pendingRequests;
}
