package com.flight.booking.service;

import com.flight.booking.dto.SearchRequestDto;
import com.flight.booking.dto.TravelOfferDto;
import com.flight.booking.model.TravelOffer;
import com.flight.booking.model.User;
import com.flight.booking.repository.TravelOfferRepository;
import com.flight.booking.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class FlightService {
    @Autowired
    private TravelOfferRepository offerRepository;
    @Autowired
    private UserRepository userRepository;

    public List<TravelOffer> getAllFlights(){
        return offerRepository.findAll();
    }
    public List<TravelOffer> search (SearchRequestDto requestDto){
        String originCity = requestDto.getOriginCity();
        String destinationCity = requestDto.getDestinationCity();
        String airline= requestDto.getAirline();
        String availableSeats = requestDto.getAvailableSeats();
        String numberOfConnections = requestDto.getNumberOfConnections();
        String order = requestDto.getOrder();

        return this.offerRepository.filterTravelOffersBasedOnKeywords(
                originCity,
                destinationCity,
                airline,
                availableSeats,
                numberOfConnections,
                order);
    }
    public TravelOffer getFlightById(Integer id) {
        return offerRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Travel offer with ID " + id + " not found."));
    }
    public TravelOffer createTravelOffer(TravelOfferDto offerDto){
        TravelOffer travelOffer = new TravelOffer();
        travelOffer.setOriginCity(offerDto.getOriginCity());
        travelOffer.setDestinationCity(offerDto.getDestinationCity());
        travelOffer.setAirline(offerDto.getAirline());
        travelOffer.setAvailableSeats(Integer.parseInt(offerDto.getAvailableSeats()));
        travelOffer.setNumberOfConnections(Integer.parseInt(offerDto.getNumberOfConnections()));
        travelOffer.setTicketPrice(Double.parseDouble(offerDto.getTicketPrice()));
        return offerRepository.save(travelOffer);
    }
    public void updateTravelOffer(Integer id, TravelOfferDto offerDto) {
        offerRepository.findById(id).map(travelOffer -> {
            mapNonNullFields(offerDto, travelOffer);
            return offerRepository.save(travelOffer);
        }).orElse(null);
    }
    public void deleteFlight(Integer id){
        offerRepository.deleteById(id);
    }
    public TravelOffer bookFlight(Integer flightId, String username) {
        TravelOffer travelOffer = offerRepository.findById(flightId)
                .orElseThrow(() -> new IllegalArgumentException("Travel offer with ID " + flightId + " not found."));

        int availableSeats = travelOffer.getAvailableSeats();
        if (availableSeats > 0) {
            travelOffer.setAvailableSeats(availableSeats - 1);
            TravelOffer bookedFlight = offerRepository.save(travelOffer);

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("User with username - " + username + " not found."));

            user.getFlight().add(bookedFlight);
            userRepository.save(user);

            return bookedFlight;
        } else {
            throw new IllegalStateException("Flight with ID " + flightId + " is fully booked.");
        }
    }
    public List<TravelOffer> getUserFlightDetails(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return user.getFlight();
    }
    public void cancelBookedTicket(String username, Integer flightId){
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        TravelOffer ticket = offerRepository.findById(flightId)
                .orElseThrow(() -> new IllegalArgumentException("Ticket not found with ID: " + flightId));;
        if (user.getFlight().contains(ticket)){
            user.cancelTicket(ticket);
            ticket.setAvailableSeats(ticket.getAvailableSeats() + 1);
            userRepository.save(user);
            offerRepository.save(ticket);
        }
    }
    public List<String> getUsersAndTickets(){
        return userRepository.findAll().stream()
                .flatMap(user -> user.getFlight().stream()
                        .map(ticket -> user.getEmail() + " - " + ticket.toString()))
                .collect(Collectors.toList());
    }
    public void clearAllTicketsAndResetAvailableSeats() {
        List<User> users = userRepository.findAll();
        for (User user : users) {
            user.getFlight().clear();
        }
        userRepository.saveAll(users);
        List<TravelOffer> travelOffers = offerRepository.findAll();
        for (TravelOffer offer : travelOffers) {
            offer.setAvailableSeats(offer.getInitialAvailableSeats());
        }
        offerRepository.saveAll(travelOffers);
    }
    private void mapNonNullFields(TravelOfferDto offerDto, TravelOffer travelOffer) {
        if (offerDto.getOriginCity() != null) {
            travelOffer.setOriginCity(offerDto.getOriginCity());
        }
        if (offerDto.getDestinationCity() != null) {
            travelOffer.setDestinationCity(offerDto.getDestinationCity());
        }
        if (offerDto.getAirline() != null) {
            travelOffer.setAirline(offerDto.getAirline());
        }
        if (offerDto.getAvailableSeats() != null) {
            travelOffer.setAvailableSeats(Integer.parseInt(offerDto.getAvailableSeats()));
        }
        if (offerDto.getNumberOfConnections() != null) {
            travelOffer.setNumberOfConnections(Integer.parseInt(offerDto.getNumberOfConnections()));
        }
        if (offerDto.getTicketPrice() != null) {
            travelOffer.setTicketPrice(Double.parseDouble(offerDto.getTicketPrice()));
        }
    }
}
