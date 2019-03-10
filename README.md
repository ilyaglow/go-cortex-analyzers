Cortex-Analyzers in Go
----------------------

This repo contains sources for
[Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) written
in Go

## List of analyzers

* [Dor](https://github.com/ilyaglow/dor) analyzer - domain ranking.
* [HaveIBeenPwned](https://haveibeenpwned.com) analyzer - check an email for
  breaches and pastes.
* [BadPackets](https://mirai.badpackets.net) analyzer - check an IP address
  presence in Mirai alike Botnet list by badpackets.net.
* [Categorify](https://categorify.org) analyzer - get categories and rating
  description of a domain address by using categorify service.

## How to build

If you have Go installed on your host you can use a simple make command:

```
make
```

You can also use docker to make builds:
```
make docker-build
```
