# iuring-mdns

MDNS (Multicast DNS) service implementation for flex-audio-service.

This library provides MDNS support including handlers for:
- NMOS HTTP services
- Ravenna HTTP services
- Ravenna RTSP services

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

This library is typically used as a submodule in the flex-audio-service project.
