package com.flight.booking.dto;

import lombok.Data;

import java.util.List;

@Data
public class PlaceSearchResponseDto {
    private List<PlaceResultDto> results;
}
