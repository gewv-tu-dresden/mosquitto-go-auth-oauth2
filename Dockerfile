#Set mosquitto and plugin versions.
#Change them as per your needs.
ARG MOSQUITTO_VERSION=2.0.12
ARG PLUGIN_VERSION=1.8.2

#Use debian:stable-slim as a builder and then copy everything.
FROM debian:stable-slim as builder
ARG MOSQUITTO_VERSION

WORKDIR /app

#Get mosquitto build dependencies.
RUN apt update && apt install -y wget build-essential cmake libssl-dev  libcjson-dev libwebsockets-dev
RUN mkdir -p mosquitto/auth mosquitto/conf.d

RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz
RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz && rm mosquitto-${MOSQUITTO_VERSION}.tar.gz 

#Build mosquitto.
RUN cd mosquitto-${MOSQUITTO_VERSION} && make CFLAGS="-Wall -O2 -I/build/lws/include" LDFLAGS="-L/build/lws/lib" WITH_WEBSOCKETS=yes && make install && cd ..

# Use golang:latest as a builder for the Mosquitto Go Auth plugin.
FROM golang:latest AS go_auth_builder

ARG PLUGIN_VERSION
ENV CGO_CFLAGS="-I/usr/local/include -fPIC"
ENV CGO_LDFLAGS="-shared -Wl,-unresolved-symbols=ignore-all"
ENV CGO_ENABLED=1

# Install TARGETPLATFORM parser to translate its value to GOOS, GOARCH, and GOARM
COPY --from=tonistiigi/xx:golang / /

RUN apt update && apt install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross

WORKDIR /app
COPY --from=builder /usr/local/include/ /usr/local/include/

#Get the plugin.
RUN wget https://github.com/iegomez/mosquitto-go-auth/archive/refs/tags/${PLUGIN_VERSION}.tar.gz \
    && ls -l \
    && tar xvf *.tar.gz --strip-components=1 \
    && rm -Rf go*.tar.gz \
    && ls -l

#Build the plugin.
RUN go build -buildmode=c-archive go-auth.go && \
    go build -buildmode=c-shared -o go-auth.so && \
	go build pw-gen/pw.go

#Get the oauth plugin
RUN go mod download golang.org/x/oauth2
COPY src/* oauth_plugin/ 
RUN export PATH=$PATH:/usr/local/go/bin && go build -buildmode=plugin -o mosquitto-go-auth-oauth2.so oauth_plugin/main.go

#Start from a new image.
FROM debian:stable-slim

#Get mosquitto dependencies.
RUN apt update && apt install -y libc-ares2 openssl uuid tini wget libssl-dev libwebsockets-dev
RUN update-ca-certificates

#Setup mosquitto env.
RUN mkdir -p /var/lib/mosquitto /var/log/mosquitto 
RUN groupadd mosquitto \
    && useradd -s /sbin/nologin mosquitto -g mosquitto -d /var/lib/mosquitto \
    && chown -R mosquitto:mosquitto /var/log/mosquitto/ \
    && chown -R mosquitto:mosquitto /var/lib/mosquitto/

#Copy confs, plugin so and mosquitto binary.
COPY --from=builder /app/mosquitto/ /mosquitto/
COPY --from=builder /usr/local/sbin/mosquitto /usr/sbin/mosquitto
COPY --from=go_auth_builder /app/pw /mosquitto/pw
COPY --from=go_auth_builder /app/go-auth.so /mosquitto/go-auth.so
COPY --from=go_auth_builder /app/mosquitto-go-auth-oauth2.so /mosquitto/mosquitto-go-auth-oauth2.so

#Uncomment to copy your custom confs (change accordingly) directly when building the image.
#Leave commented if you want to mount a volume for these (see docker-compose.yml).

# COPY example_conf/mosquitto.conf /etc/mosquitto/mosquitto.conf
# COPY example_conf/conf.d/go-auth.conf /etc/mosquitto/conf.d/go-auth.conf
# COPY example_conf/auth/acls /etc/mosquitto/auth/acls
# COPY example_conf/auth/passwords /etc/mosquitto/auth/passwords

#Expose tcp and websocket ports as defined at mosquitto.conf (change accordingly).
EXPOSE 1883 1884

ENTRYPOINT ["sh", "-c", "/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf" ]
