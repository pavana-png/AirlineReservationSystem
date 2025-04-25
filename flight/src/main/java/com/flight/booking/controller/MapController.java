package com.flight.booking.controller;

import com.flight.booking.dto.PlaceSearchResponseDto;
import com.flight.booking.service.FlightService;
import com.flight.booking.service.MapService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import reactor.core.publisher.Mono;

@Controller
public class MapController {
    @Autowired
    private FlightService flightService;
    @Autowired
    private MapService mapService;
    @Value("${google.apikey:AIzaSyDvcluySCLuXyKovkbT2HkuhAPD6t6DOH4}")
    private String googleApiKey;

    @GetMapping("/map")
    public String getMap(Model model) {
        model.addAttribute("apikey", googleApiKey);
        model.addAttribute("flights", flightService.getAllFlights());
        return "map";
    }
    @Async
    @GetMapping("/map/siteAttractions")
    public String getSiteAttractions(Model model){
        model.addAttribute("flights", flightService.getAllFlights());
        return "siteAttractions";
    }
    @PostMapping("/map/displaySiteAttractions")
    public String displaySiteAttractions(@ModelAttribute("city") String city, Model model){
        Mono<PlaceSearchResponseDto> result = mapService.getRestaurantsInState(city);

        PlaceSearchResponseDto response = result.block();

        if (response == null || response.getResults() == null || response.getResults().isEmpty()) {
            model.addAttribute("notFound", true);
        } else {
            model.addAttribute("result", response);
            model.addAttribute("flights", flightService.getAllFlights());
        }

        return "siteAttractions";
    }
}
