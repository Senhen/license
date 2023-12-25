# Use the official Ubuntu 20.04 image as base
FROM ubuntu:20.04

# Disable the interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update and install gcc, and any other dependencies you might have.
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled test executable from your host to the container. Make sure to compile your application first.
COPY ./test /usr/src/app/

# Set working directory
WORKDIR /usr/src/app

# Make the test binary executable
RUN chmod +x /usr/src/app/test

# Command to execute when the container starts. Replace test with your executable name.
CMD ["/usr/src/app/test"]