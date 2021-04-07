FROM golang

WORKDIR /nats

COPY . .

RUN go mod init
RUN go mod tidy
RUN go mod vendor

RUN go install accounts

ENTRYPOINT["go", "run main.go"]
