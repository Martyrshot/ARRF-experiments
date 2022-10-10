# OQS-bind test network
This repo contains code for testing and evaluating both a sequential and batched versions of RRFrag daemons and the ARRF protocol. Test DNS networks are constructed using Docker and network conditions are set by the `./set_network_conditions.bash` script.


## Instructions
### Building the system
To run the experiments, first copy the source code for either the batched or sequential directories into the `rrfrag-daemon/` directory. Then run `python3 build_docker_compose.py --maxudp UDPSIZE --alg ALGNAME [--bypass]`. `--bypass` should be used when running the experiments without the RRFrag daemon. `--maxudp` and `--alg` must always be specified. Currently we support the `FALCON512`, `DILITHIUM2`, `SPHINCS+-SHA256-128S`, `RSASHA256`, and `ECDSA256`.

Now navigate to `build` and use `docker compose build` to finish building the network. 

### Running the network
Once the network is built, navigate back to the root directory and run the `run_scenarios.bash` to start running the experiemnts.  Once all of the containers are a particular experiment are running, you can attach to any of them by using `docker exec -it <CONTAINER_NAME> bash`.

### Configuring a custom network
The build script is fairly naive, so it requires that you write your own configure file (named.conf) for each zone. The build script does not sanity check if the zone configureation file makes sense, or if it's even syntactically correct.

There are several build script config json files, namely: `networks.json`, `resolvers.json`, `name_servers.json`, `hosts.json`, and `clients.json`. The build script uses these, combined with that corresponding directories to construct each container.
(ex: `resolvers/` will be used to build every resolver specified in `resolvers.json`). In general, you can probably ignore `networks.json`, unless you need to specify a different ip range.
