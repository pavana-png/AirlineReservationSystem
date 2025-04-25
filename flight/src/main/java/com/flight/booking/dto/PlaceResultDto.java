package com.flight.booking.dto;

import lombok.Data;

import java.util.List;

@Data
public class PlaceResultDto {
    private String name;
    private String formatted_address;
    private List<String> types;
}
