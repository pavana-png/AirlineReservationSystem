package com.flight.booking.controller;


import com.flight.booking.dto.TravelOfferDto;
import com.flight.booking.service.FlightService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

//@PreAuthorize("hasAuthority('ADMIN')")
@Controller
public class AdminFlightController {
    @Autowired
    private FlightService flightService;
    @GetMapping("/admin/flight/addFlight")
    @PreAuthorize("hasRole('ADMIN')")
    public String getCreateFlight(Model model) {
        model.addAttribute("flights", flightService.getAllFlights());
        return "newFlight";
    }
    @PostMapping("/admin/flight/addFlight")
    @PreAuthorize("hasRole('ADMIN')")
    public String createFlight(@ModelAttribute("flight") TravelOfferDto offerDto, Model model) {
        flightService.createTravelOffer(offerDto);
        model.addAttribute("flights", flightService.getAllFlights());
        return "newFlight";
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/bookedTickets")
    public String getBookedTickets(Model model){
        List<String> results = flightService.getUsersAndTickets();
        model.addAttribute("results", results);
        return "flightHistoryAdmin";
    }
    @GetMapping("/admin/flight")
    @PreAuthorize("hasRole('ADMIN')")
    public String getUpdateFlight(@RequestParam Integer id,
                                  @ModelAttribute("update") TravelOfferDto offerDto) {
        //TravelOffer updatedFlight = flightService.updateTravelOffer(id, offerDto);
        return "updateFlight";
    }

    @PutMapping("/admin/flight")
    @PreAuthorize("hasRole('ADMIN')")
    public String updateFlightDetails(@RequestParam Integer id,
                                      @RequestBody TravelOfferDto offerDto,
                                      Model model,
                                      RedirectAttributes redirectAttributes) {
        flightService.updateTravelOffer(id, offerDto);
        model.addAttribute("ticket", flightService.getFlightById(id));
        redirectAttributes.addAttribute("id", id);
        redirectAttributes.addAttribute("success", true);
        return "redirect:/admin/flight/updateFlight";
    }
    @DeleteMapping("/admin/flight")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteFlight(@RequestParam Integer id) {
        flightService.deleteFlight(id);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/bookedTickets/clear")
    public String clearBookedTickets(Model model){
        //List<String> results = flightService.getUsersAndTickets();
        flightService.clearAllTicketsAndResetAvailableSeats();
        model.addAttribute("results", null);
        //return "flightHistoryAdmin";
        return "redirect:/admin/bookedTickets";
    }
}
