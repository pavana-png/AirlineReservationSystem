INSERT INTO travel_offers (origin_city, destination_city, airline, available_seats, number_of_connections, ticket_price)
VALUES
('New York', 'Los Angeles', 'Delta Airlines', 150, 1, 250.00),
('Los Angeles', 'San Francisco', 'United Airlines', 100, 0, 180.00),
('Chicago', 'Miami', 'American Airlines', 200, 2, 300.00),
('Miami', 'Seattle', 'Alaska Airlines', 120, 1, 350.00),
('Seattle', 'Boston', 'JetBlue Airways', 180, 1, 280.00),
('Boston', 'Denver', 'Southwest Airlines', 160, 0, 220.00),
('Denver', 'Dallas', 'Frontier Airlines', 140, 0, 200.00),
('Dallas', 'Houston', 'Spirit Airlines', 170, 0, 190.00),
('Houston', 'Atlanta', 'Delta Airlines', 190, 0, 230.00),
('Atlanta', 'Orlando', 'American Airlines', 150, 0, 180.00),
('Orlando', 'Las Vegas', 'Southwest Airlines', 200, 1, 320.00),
('Las Vegas', 'Phoenix', 'Allegiant Air', 130, 0, 210.00),
('Phoenix', 'San Diego', 'Sun Country Airlines', 180, 0, 240.00),
('San Diego', 'Portland', 'Alaska Airlines', 160, 1, 270.00),
('Portland', 'Minneapolis', 'Delta Airlines', 140, 1, 260.00),
('Minneapolis', 'Detroit', 'American Airlines', 170, 0, 220.00),
('Detroit', 'Philadelphia', 'Frontier Airlines', 190, 0, 230.00),
('Philadelphia', 'Charlotte', 'American Airlines', 150, 0, 180.00),
('Charlotte', 'Washington D.C.', 'JetBlue Airways', 200, 0, 240.00),
('Washington D.C.', 'New York', 'United Airlines', 180, 0, 220.00);
INSERT INTO roles(name)
VALUES
('USER'),
('ADMIN');
