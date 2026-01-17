
iuring based MDNS server library
===============================

This is a C++ library that you link against your application to give it MDNS
server abilities.
The advantages over avahi/zeroconf libs are:
- single library, no client-library and seperate daemon
- small footprint
- easy to add your services
- fast/low-latency

Its based on iuring (which is a C++ library that wraps liburing for fast, low-latency network access).
