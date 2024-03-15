# Start from the latest golang base image
FROM golang:1.18 as builder

# Set the Current Working Directory inside the container
WORKDIR /workspace

COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux  go build -a -o license_sign main.go

FROM ubuntu:22.04 as signTools-builder
WORKDIR /usr/src/

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY base /usr/src/base
COPY signTools /usr/src/signTools

RUN g++ -std=c++11 /usr/src/base/test/ctest/license_sign.cpp -o /usr/src/signTools/license_sign -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lssl -lcrypto

# Start a new stage from ubuntu 22.04 base image
FROM ubuntu:22.04

WORKDIR /usr/src/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /workspace/license_sign .
COPY --from=signTools-builder /usr/src/signTools ./signTools

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Expose port 9999 to the outside
EXPOSE 9999

# Command to run the executable
ENTRYPOINT ["/usr/src/license_sign"]