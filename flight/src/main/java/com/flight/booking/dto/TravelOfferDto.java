package com.flight.booking.dto;

import lombok.Data;

@Data
public class TravelOfferDto {
    private String originCity;
    private String destinationCity;
    private String airline;
    private String availableSeats;
    private String numberOfConnections;
    private String ticketPrice;
}
