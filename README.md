# OQS-bind test network
This repo contains a python script, and some template files, which creates a test DNS. Currently all repos that bind, liboqs, and OQS-OpenSSL are pulled from are hard coded. This should be changed in the future. Docker is required.


## Instructions
### Building the system
To run the test DNS, navigate to the root of this repo, and run `python3 build_docker_compose.py`, which creates a directory `build/`. Navigate to the newly created `build/` directory, and run `docker-compose build`. 

### Running the network
You'll need either multiple terminal windows, or a terminal multiplexer (I like tmux) in order to interact with the various docker containers that get launched.

Once the network is built, you'll be able to launch it with `docker-compose up` when inside the `build/` directory. Once all of the instances have `started`, you can attach to any of them by using `docker exec -it <CONTAINER_NAME> bash`.

### Configuring a custom network
The build script is fairly naive, so it requires that you write your own configure file (named.conf) for each zone. The build script does not sanity check if the zone configureation file makes sense, or if it's even syntactically correct.

There are several build script config json files, namely: `networks.json`, `resolvers.json`, `name_servers.json`, `hosts.json`, and `clients.json`. The build script uses these, combined with that corresponding directories to construct each container.
(ex: `resolvers/` will be used to build every resolver specified in `resolvers.json`). In general, you can probably ignore `networks.json`, unless you need to specify a different ip range.
