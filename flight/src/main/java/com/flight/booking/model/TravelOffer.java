package com.flight.booking.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@DynamicUpdate
@Table(name = "travel_offers")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TravelOffer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(name = "origin_city")
    private String originCity;
    @Column(name = "destination_city")
    private String destinationCity;
    @Column(name = "airline")
    private String airline;
    @Column(name = "available_seats")
    private int availableSeats;
    @Column(name = "number_of_connections")
    private int numberOfConnections;
    @Column(name = "ticket_price")
    private double ticketPrice;

    public int getInitialAvailableSeats() {
        return availableSeats;
    }
    @Override
    public String toString(){
        return id + "_" + airline;
    }
}
