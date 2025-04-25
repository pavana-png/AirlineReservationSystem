package com.flight.booking.repository;

import com.flight.booking.model.TravelOffer;

import java.util.List;

public interface CustomTravelOfferRepository {
    List<TravelOffer> filterTravelOffersBasedOnKeywords(
            String originCity,
             String destinationCity,
             String airline,
             String availableSeats,
             String numberOfConnections,
             String order);
}
