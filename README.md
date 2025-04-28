# NetworkTrafficAnalyzer

## Description

The **NetworkTrafficAnalyzer** is a Java-based application designed to capture and analyze network traffic. The project utilizes **PCAP4J** library for packet capturing and **Apache Maven** for project management. The primary purpose of this project is to gather network packets, analyze their data, and help in identifying network-related issues or vulnerabilities. 

## Features

- Capture network packets.
- Parse packet data.
- Display the details of each captured packet, including protocols, source/destination IP addresses, and other relevant information.
- Simple analysis to help understand network traffic flow.

## Prerequisites

Before running the project, ensure that you have the following installed:

- **Java** (version 8 or higher)
- **Maven**
- **PCAP4J library** for packet capturing

## Setup

1. Clone the repository:

    ```bash
    git clone https://github.com/cyber-alok/NetworkTrafficAnalyzer.git
    ```

2. Navigate to the project directory:

    ```bash
    cd NetworkTrafficAnalyzer
    ```

3. Build the project using Maven:

    ```bash
    mvn clean install
    ```

4. Run the application:

    ```bash
    mvn exec:java
    ```

## Code Explanation

- **NetworkCapture.java**: Handles the network traffic capture using PCAP4J.
- **PacketAnalyzer.java**: Processes and analyzes the captured network packets.
- **Main.java**: The entry point of the application, starts the packet capture and analysis process.

## Troubleshooting

If you face issues with network capturing:

- Ensure that your network adapter is properly configured for packet capturing.
- Run the application with administrator privileges if required.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

