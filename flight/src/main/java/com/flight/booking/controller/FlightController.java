package com.flight.booking.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.flight.booking.dto.SearchRequestDto;
import com.flight.booking.model.TravelOffer;
import com.flight.booking.service.CurrencyConversionService;
import com.flight.booking.service.FlightService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class FlightController {

    @Autowired
    private FlightService flightService;

    @Autowired
    private CurrencyConversionService conversionService;

    // @GetMapping("/flights/book-flight")
    // public String getBookFlight(@RequestParam Integer id, Model model) throws JsonProcessingException {
    //     model.addAttribute("ticket", flightService.getFlightById(id));
    //     model.addAttribute("codes",  conversionService.getCodes());
    //     return "bookFlight";
    // }
    @PostMapping("/flights/book-flight")
public String bookFlight(@RequestParam(name = "id", required = true) Integer id, Model model, RedirectAttributes redirectAttributes) {
    if (id == null) {
        throw new RuntimeException("Flight ID is required but was null.");
    }
    
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
        return "redirect:/login";
    }

    String username = authentication.getName();
    TravelOffer bookedFlight = flightService.bookFlight(id, username);
    if (bookedFlight == null) {
        throw new RuntimeException("Booking failed for flight ID: " + id);
    }

    redirectAttributes.addAttribute("id", id);
    redirectAttributes.addAttribute("success", true);

    return "redirect:/flights/book-flight?id=" + id;
}



@GetMapping("/flights/book-flight")
public String showBookingPage(@RequestParam Integer id, Model model) {
    TravelOffer ticket = flightService.getFlightById(id);
    if (ticket == null) {
        throw new RuntimeException("Flight not found with ID: " + id);
    }
    model.addAttribute("ticket", ticket);
    return "bookFlight"; // Ensure you have a bookFlight.html page
}


    @GetMapping("/flights")
    public String getAllFlights(Model model) {
        model.addAttribute("flights", flightService.getAllFlights());
        return "flights";
    }

    @GetMapping("/flights/{id}")
    public String getSingleFlight(@PathVariable Integer id, Model model) {
        TravelOffer flight = flightService.getFlightById(id);
        return "flights";
    }

    @GetMapping("/flights/search")
   public String searchByFlightDetails(Model model) {
        //List<TravelOffer> flights = flightService.getAllFlights();
        model.addAttribute("flights", flightService.getAllFlights());
        model.addAttribute("results", null);
        return "searchFlight";
    }
    @PostMapping("/flights/search")
    public String searchByFlightDetails(
            @ModelAttribute("search") SearchRequestDto requestDto,
            Model model) {
        if (requestDto == null) {
            model.addAttribute("NullDtoError", "Fill missing fields");
            model.addAttribute("flights", flightService.getAllFlights());
            return "searchFlight";
        }
        String originCity = requestDto.getOriginCity();
        String destCity = requestDto.getDestinationCity();
        if (originCity.equals(destCity)) {
            model.addAttribute("DestinationError", "Departure and Destination city can't be same");
            model.addAttribute("flights", flightService.getAllFlights());
            return "searchFlight";
        }

        List<TravelOffer> flights = flightService.search(requestDto);
        if (flights.isEmpty()) {
            model.addAttribute("notFound", "No record found");
            model.addAttribute("flights", flightService.getAllFlights());
        } else {
            model.addAttribute("flights", flightService.getAllFlights());
            model.addAttribute("results", flights);
        }
        return "searchFlight";
    }

    @GetMapping("/flights/convertPrice")
    public String getCurrencyCodes(@RequestParam Integer id, Model model) throws JsonProcessingException {
        model.addAttribute("codes",  conversionService.getCodes());
        return "convertPrice";
    }
    @PostMapping("/flights/convertCurrency")
    public String convertTicketPrice(@RequestParam Integer id,
                                     @RequestParam String desiredCur,
                                     Model model,
                                     RedirectAttributes redirectAttributes) throws JsonProcessingException {
        TravelOffer ticket= flightService.getFlightById(id);
        double convertedPrice = conversionService.changePriceToDesiredCurrency(ticket.getTicketPrice(), desiredCur);
        ticket.setTicketPrice(convertedPrice);
        redirectAttributes.addAttribute("id", id);
        model.addAttribute("ticket", ticket);
        model.addAttribute("codes",  conversionService.getCodes());
        return "convertPrice";
    }

    @GetMapping("/flights/history")
    public String getUserTicketHistory(Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        String username = authentication.getName();
        model.addAttribute("flights", flightService.getUserFlightDetails(username));
        return "flightHistoryUser";
    }
    @GetMapping("/flights/cancel-flight")
    public String cancelTicket(@RequestParam Integer id, Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        String username = authentication.getName();
        flightService.cancelBookedTicket(username, id);
        model.addAttribute("flights", flightService.getUserFlightDetails(username));
        return "flightHistoryUser";
    }

}