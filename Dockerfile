# Start from the latest golang base image
FROM golang:1.18 as builder

# Set the Current Working Directory inside the container
WORKDIR /workspace

COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux  go build -a -o license_sign main.go

# Start a new stage from ubuntu 22.04 base image
FROM ubuntu:22.04

WORKDIR /usr/src/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /workspace/license_sign .

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Expose port 9999 to the outside
EXPOSE 9999

# Command to run the executable
ENTRYPOINT ["/usr/src/license_sign"]