#! /bin/bash

export OUTPUTDIR="$(pwd)/x86_res/sequential/nodelay_unlimited"
export UDPSIZES="65355 1232 512 256"
export ALGS="FALCON512 DILITHIUM2 SPHINCS+-SHA256-128S"
export BUILDDIR="$(pwd)/build"
export WORKINGDIR="$(pwd)"
mkdir -p $OUTPUTDIR
for ALG in $ALGS
do
	echo $ALG
	for UDPSIZE in $UDPSIZES
	do
		cd $WORKINGDIR
		python3 build_docker_compose.py --maxudp $UDPSIZE --alg $ALG <<< "Y"
		cd $BUILDDIR
		docker compose down
		docker compose build
		cd $WORKINGDIR
		./run_exps_nc.bash 0 1000 | tee scratch.log
		echo "$ALG"_"$UDPSIZE"": " $(tail -n 1 scratch.log) >> results_summary.log
		rm scratch.log
		cd $BUILDDIR/dig_logs
		tar -cvf "X86_64_""$ALG"_"$UDPSIZE"".tar" *
		mv  "X86_64_""$ALG"_"$UDPSIZE"".tar" $OUTPUTDIR
	done
done
