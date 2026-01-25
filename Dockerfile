FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build using your Makefile
RUN make

# Adjust this if your Makefile outputs a different binary name
CMD ["./university_app"]
