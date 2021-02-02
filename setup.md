## Create Accounts

- operator account
- system account (nats uses to communicate with account server)
- admin account (robot ac for other api calls)
  imports:
   - stream (<- incoming): Events, prefix: user.x (x == user_id)
   - service (outgoing -> user): "user.x.Notifications"
- user accoun (eg BB user)
   exports:
   - stream (outgoing): Events
   - service (incoming): Notifications
     - must be different for each user (so add prefix)
- server.conf

```shell
$ cd $HOME/go/src/github.com/appscode/demo-cloudevents/nats

$ go run accounts/main.go
Configuration directory:  $HOME/go/src/github.com/appscode/demo-cloudevents/nats/confs/ac_store

SOAN7F2O4UDIXAVNMMVJGTXKJVKCNBNGVMISSJ7DRZWDTPDLUXFOPSMWTM
2021/01/26 04:48:24 NATS Server with Jetstream started...
2021/01/26 04:48:24 Everything is okay, I guess
```

*Gitea*
- Upload (POST) to nats-account-server
  - https://github.com/appscode/gitea/blob/20d793f2a82a9fa4676b52e7d88a7da216f23d18/models/nats_account.go#L28
  - https://github.com/appscode/gitea/blob/20d793f2a82a9fa4676b52e7d88a7da216f23d18/modules/nats/nats_server.go#L46

## Install nats server

```shell
$ cd $HOME/go/src/github.com/nats-io/nats-server
$ go install -v ./...
```

## Install nats account server

```shell
$ cd $HOME/go/src/github.com/nats-io/nats-account-server
$ go install -v ./...
```

## Run nats account server

```shell
$ cd $HOME/go/src/github.com/appscode/demo-cloudevents/nats

$ nats-account-server -c confs/ac_store/nas.conf
```

## Run nats server

```shell
$ cd $HOME/go/src/github.com/appscode/demo-cloudevents/nats

$ nats-server -c confs/ac_store/server.conf
```

## Push created account server to nats account server
```shell
$ cd $HOME/go/src/github.com/appscode/demo-cloudevents/nats

$ go run accounts-push/main.go
```

## Send/Receive Simulations (using nats official sdk)

- User x publishes
- Admin consumes (receives)

```shell
$ cd $HOME/go/src/github.com/appscode/demo-cloudevents/nats

$ go run server/main.go
2021/01/26 05:16:49 A stream named `ReceivedEvents` has been created
2021/01/26 05:16:49 A consumer named `ProcessEvents` has been created
Events <==> Hello there, at 2021-01-26 05:16:51.41368682 -0800 PST m=+2.031811108
Events <==> Hello there, at 2021-01-26 05:16:53.413720583 -0800 PST m=+4.031844931
```


## sender / receiver demo (using CloudEvents sdk)

```shell
$ cd $HOME/go/src/github.com/appscode/demo-cloudevents/nats

$ go run receiver/main.go
2021/01/26 05:36:37 Jetstream receiver to `ProcessEvents` started...

$ go run sender/main.go
```

## Publish/Subscribe via `Service` type Export/Import

```shell
$ nats -s nats://localhost:5222 sub 'Notifications' --creds confs/ac_store/x.creds

$ nats -s nats://localhost:5222 pub 'user.x.Notifications' "Hello there 6" --creds confs/ac_store/admin.creds
```

## Push Consumer

```shell
$ go run push-consumer/main.go
```

- It creates a `stream` for subject `Notifications` and also a push based consumer with with `DeliveryTarget : my.Notifications`.
- After creating these, messages are published to `user.x.Notifications` by admin.
- Then user x listens to `my.Notifications` and acknowledges them.

## TODO:

- License server creates a BB account (issues nats account, uses BB user_id as user.{user_id} stream prefix)
- operator sends data using nats token

