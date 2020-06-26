# Ping: Compatible on both Linux and MacOS
## Synopsis
```
./ping [-c count] [-i interval] [-m TTL] [-s packetsize] [-t timeout] host
```
This utility requires root privilege
## Parameters
The utility is designed to resemble BSD version of ping, including available options and behaviors.
* `count`: Number of ICMP echos to be sent
* `interval`: The interval between each ICMP echo, The default is 1 second
* `TTL`: Time-to-live
* `packetsize`: The size of each ICMP packet in bytes. The default is 56 bytes
* `timeout`: Number of seconds the program will run.
