package com.flight.booking.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flight.booking.dto.PlaceSearchResponseDto;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class MapService {
    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final String API_URL = "https://maps.googleapis.com/maps/api/place/textsearch/json";
    private final String API_KEY = "AIzaSyDvcluySCLuXyKovkbT2HkuhAPD6t6DOH4";
    public MapService(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.baseUrl(API_URL).build();
        this.objectMapper = objectMapper;
    }
    public Mono<PlaceSearchResponseDto> getRestaurantsInState(String state) {
        String encodedState = URLEncoder.encode(state, StandardCharsets.UTF_8);
        String query = String.format("%s+point+of+interest", encodedState);

        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("query", query)
                        .queryParam("language", "en")
                        .queryParam("region", "us")
                        .queryParam("key", API_KEY)
                        .build())
                .retrieve()
                .bodyToMono(String.class)
                .map(response -> {
                    try {
                        return objectMapper.readValue(response, PlaceSearchResponseDto.class);
                    } catch (IOException e) {
                        throw new RuntimeException("Error parsing JSON response", e);
                    }
                });
    }
}
