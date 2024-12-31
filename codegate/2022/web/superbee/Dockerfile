# Use the official Ubuntu 22.04 base image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the Go application source code to the container
COPY . .

# Build the Go application
RUN go build -o app main.go

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["./app"]