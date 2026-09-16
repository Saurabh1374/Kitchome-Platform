package com.kitchome.auth.payload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PromotionRequestDTO {
    private String serviceId; // e.g. "kitchome-rag"
    private Integer requestedClearance; // 1, 2, or 3
    private String requestedRole; // e.g. "member"
    private List<String> requestedScopes; // e.g. ["rag:read", "ingestion:write"]
    private String justification;
}
