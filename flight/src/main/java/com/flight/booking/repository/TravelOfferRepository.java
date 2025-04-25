package com.flight.booking.repository;

import com.flight.booking.model.TravelOffer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TravelOfferRepository extends JpaRepository<TravelOffer, Integer>, CustomTravelOfferRepository {
}
