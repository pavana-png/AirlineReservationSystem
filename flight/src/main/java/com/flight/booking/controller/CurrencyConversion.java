package com.flight.booking.controller;

import com.flight.booking.dto.TravelOfferDto;
import com.flight.booking.model.TravelOffer;
import com.flight.booking.service.CurrencyConversionService;
import com.flight.booking.service.FlightService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/currency")
public class CurrencyConversion {
    @Autowired
    private CurrencyConversionService conversionService;
    @Autowired
    private FlightService flightService;

    @GetMapping("/convert/{ticketId}")
    public Object convertTicketPrice(@PathVariable Integer ticketId,
                                     @RequestParam String desiredCur){
        TravelOffer ticket= flightService.getFlightById(ticketId);
        double convertedPrice = conversionService.changePriceToDesiredCurrency(ticket.getTicketPrice(), desiredCur);
        TravelOfferDto offerDto = new TravelOfferDto();
        offerDto.setTicketPrice(String.valueOf(convertedPrice));
        flightService.updateTravelOffer(ticketId, offerDto);
        return convertedPrice;
    }
}
