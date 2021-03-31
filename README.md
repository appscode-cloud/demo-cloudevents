# `Classic Nats`, `Jetstream` and `Websocket`

**Design:** https://github.com/appscode/nats-design

## Classic `NATS` Server

- **Run `nats-account-server`**

  ```sh
  $ ./nats-account-server -c account-server.conf &
  ```

- **Now checkout to `<project-directory>/nats-v2` directory.**

  ```console
  $ cd nats-v2
  ```

- **All necessary accounts are already created. Even then you want to create again, run _`( Optional )`_:**

  ```sh
  $ go run accounts/main.go
  ```

- **Now start the `Classic Nats` server**

  ```sh
  $ go run server/main.go &
  ```

- **Start a subscriber to `Classic Nats` which will receive all the events sent to `*.Events`. This program redirects all the incoming `events` to the `jetstream` server `Stream` named `ReceivedEvents`.**

  ```sh
  $ go run sub/main.go
  ```

<br><hr><br>

## Jetstream Server

- **Checkout to the `<project-directory>/nats` directory**

  ```sh
  $ cd nats
  ```

- **All necessary accounts are already created. Even then you want to create again, run _`( Optional )`_:**

  ```sh
  $ go run accounts/main.go
  ```

- **Start the `Jetstream` server**

  ```sh
  $ go run server/main.go &
  ```

- **Start the receiver which checks all the `events` sent to the stream and after processing the events it sends them to the `user's` `Notifications` channel.**

  ```sh
  $ go run receiver/main.go
  ```

<br><hr><br>

## Websocket

- **Checkout to the `<project-directory>/nats.ws` directory**

  ```sh
  $ cd nats.ws
  ```

- **Serve the `html` file**

  ```sh
  $ npm install http-server -g
  $ http-server -o
  ```
