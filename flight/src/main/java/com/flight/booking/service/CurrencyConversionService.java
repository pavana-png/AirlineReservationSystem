package com.flight.booking.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;

@Service
public class CurrencyConversionService {
    private final WebClient.Builder webClientBuilder;

    public CurrencyConversionService() {
        this.webClientBuilder = WebClient.builder();
    }

    public double currencyConverter(String toCur) {
        try {
            URI currencyUrl = URI.create(String.format("http://localhost:8080/aCurConvRS/webresources/exRate?from=%s&to=%s", "USD", toCur));
            String exchangeRateStr = webClientBuilder.build()
                    .get()
                    .uri(currencyUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            if (exchangeRateStr != null) {
                String[] parts = exchangeRateStr.split("@");
                String exchangeRateValue = parts[0].trim();
                return Double.parseDouble(exchangeRateValue);
            } else {
                throw new RuntimeException("Exchange rate not available");
            }
        } catch (NumberFormatException e) {
            throw new RuntimeException("Invalid exchange rate format", e);
        }
    }
    public Object getCodes() throws JsonProcessingException {
        URI codeUrl = URI.create("http://localhost:8080/aCurConvRS/webresources/curCodes");
        String currencyCodes = webClientBuilder.build()
                .get()
                .uri(codeUrl)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(currencyCodes, Object.class);
    }
    public double changePriceToDesiredCurrency(double amount, String toCur) {
        double exchangeRate = currencyConverter(toCur);
        double convertedAmount = amount * exchangeRate;
        return Double.parseDouble(String.format("%.2f", convertedAmount));
    }
}
