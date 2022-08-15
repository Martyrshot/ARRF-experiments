#! /bin/bash

export OUTPUTDIR="$(pwd)/x86_res/sequential/100ms_50mbps"
export UDPSIZES="1232 512 256"
export ALGS="DILITHIUM2 SPHINCS+-SHA256-128S"
export BUILDDIR="$(pwd)/build"
export WORKINGDIR="$(pwd)"
mkdir -p $OUTPUTDIR
for ALG in $ALGS
do
	echo $ALG
	for UDPSIZE in $UDPSIZES
	do
		cd $WORKINGDIR
		if [[ $UDPSIZE == "notcp" ]]
		then
			python3 build_docker_compose.py --bypass --maxudp 1232 --alg $ALG <<< "Y"
		else
			python3 build_docker_compose.py --maxudp $UDPSIZE --alg $ALG <<< "Y"
		fi
		cd $BUILDDIR
		docker compose down
		docker compose build
		cd $WORKINGDIR
		if [[ $ALG == SPHINCS+-SHA256-128S ]]
		then
			echo "Being safe..."
			cp tmux-run-docker-part2_sphincs+_safe.bash build/tmux-run-docker-part2.bash
		fi
		if [[ $ALG == DILITHIUM2 ]]
		then
			if [[ $UDPSIZE -eq 256 ]]
			then
				echo "Being safe..."
				cp tmux-run-docker-part2_dilithium2_safe.bash build/tmux-run-docker-part2.bash
			fi
		fi

		./run_exps.bash 0 1000 | tee scratch.log
		echo "$ALG"_"$UDPSIZE"": " $(tail -n 1 scratch.log) >> results_summary.log
		rm scratch.log
		cd $BUILDDIR/dig_logs
		tar -cvf "X86_64_""$ALG"_"$UDPSIZE"".tar" *
		mv  "X86_64_""$ALG"_"$UDPSIZE"".tar" $OUTPUTDIR
	done
done
