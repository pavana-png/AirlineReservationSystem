package com.flight.booking.repository;

import com.flight.booking.model.TravelOffer;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class CustomTravelOfferRepositoryImpl implements CustomTravelOfferRepository{
    private final EntityManager entityManager;

    @Autowired
    public CustomTravelOfferRepositoryImpl(EntityManager entityManager){
        this.entityManager = entityManager.getEntityManagerFactory().createEntityManager();
    }

    @Override
    public List<TravelOffer> filterTravelOffersBasedOnKeywords(
            String originCity,
            String destinationCity,
            String airline,
            String availableSeats,
            String numberOfConnections,
            String order
    ) {
        StringBuilder builder = new StringBuilder("SELECT * FROM travel_offers WHERE 1=1");

        appendCondition(builder, "origin_city", originCity);
        appendCondition(builder, "destination_city", destinationCity);
        appendCondition(builder, "airline", airline);
        appendNumericCondition(builder, "available_seats", availableSeats, ">=");
        appendNumericCondition(builder, "number_of_connections", numberOfConnections, "<=");

        if (order != null && !order.isEmpty()) {
            builder.append(" ORDER BY ticket_price ").append(order.toUpperCase());
        }

        Query q = entityManager.createNativeQuery(builder.toString(), TravelOffer.class);
        return  q.getResultList();
    }
    private void appendCondition(StringBuilder builder, String fieldName, String fieldValue) {
        if (fieldValue != null && !fieldValue.isEmpty()) {
            builder.append(" AND ").append(fieldName).append(" = '").append(fieldValue).append("'");
        }
    }

    private void appendNumericCondition(StringBuilder builder, String fieldName, String fieldValue, String operator) {
        if (fieldValue != null && !fieldValue.isEmpty()) {
            int value = Integer.parseInt(fieldValue);
            builder.append(" AND ").append(fieldName).append(" ").append(operator).append(" ").append(value);
        }
    }
}
