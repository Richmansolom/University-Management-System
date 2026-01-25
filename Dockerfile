FROM ubuntu:22.04

# Install build tools
RUN apt-get update && \
    apt-get install -y g++ make && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source files
COPY src/ums.cpp /app/ums.cpp

# Compile the application
RUN g++ -std=c++17 ums.cpp -o ums

# Default command
CMD ["./ums"]
