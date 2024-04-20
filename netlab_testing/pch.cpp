//
// pch.cpp
//

#include "pch.h"

void handleConnections(SOCKET server_socket, size_t expected_bytes) {
	struct sockaddr_in client_addr;
	int client_addr_len = sizeof(client_addr);
	int total = 0;
	char* a = new char[expected_bytes];
	std::fill(a, a + expected_bytes, 'T');


	while (true) {
		// Accept incoming connections
		SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
		if (client_socket == INVALID_SOCKET) {
			std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
			return;
		}

		std::cout << "Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;

		// Receive data from the client
		char* buffer = new char[expected_bytes];
		memset(buffer, 0, expected_bytes); // Clear the buffer (optional
		int bytes_received;
		while ((bytes_received = recv(client_socket, buffer + total, sizeof(buffer), 0)) > 0) {
			total += bytes_received;
			if (total >= expected_bytes)
			{
				break;
			}
		}

		std::cout << "Total bytes received: " << total << std::endl;
		auto c = memcmp(buffer, a, expected_bytes);
		if (memcmp(buffer, a, expected_bytes) == 0)
		{
			std::cout << "Data received successfully" << std::endl;
		}
		else
		{
			std::cerr << "Data received is corrupted" << std::endl;
		}

		// Check if recv failed
		if (bytes_received == SOCKET_ERROR) {
			std::cerr << "Receive failed: " << WSAGetLastError() << std::endl;
		}

		// Close client socket
		closesocket(client_socket);
		delete buffer;
		delete a;
		break;
	}
}