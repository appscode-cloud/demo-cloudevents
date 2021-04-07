FROM golang

WORKDIR /src

COPY . .

RUN go build -o accounts -mod=vendor nats/accounts/main.go

ENTRYPOINT ["./accounts"]
