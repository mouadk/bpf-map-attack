FROM alpine:latest

RUN apk add --no-cache build-base linux-headers
WORKDIR /home/app
COPY src .
COPY Makefile .
RUN make
