# L2Bridge  plugin (Windows)

## Overview

With L2bridge plugin, all containers (on the same host) are plugged into an L2Bridge network that has one endpoint in the host namespace.


## Example configuration
```
{
	"name": "mynet",
	"type": "l2bridge",
	"ipam": {
		"type": "host-local",
		"subnet": "10.10.0.0/16"
	}
}
```

## Network configuration reference

* `name` (string, required): the name of the network.
* `type` (string, required): "bridge".
* `ipam` (dictionary, required): IPAM configuration to be used for this network.
