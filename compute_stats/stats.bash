#! /bin/bash

export TARDIR=/home/ubuntu/mmath-thesis-testing/x86_res/batched
export SCENARIOS="10ms_128kbps 10ms_50mbps"
export MAXUDP="65355 1232 512 256"
export STATSDIR=$(pwd)
export WORKDIRROOT=$STATSDIR"/batched"
export ALGS="FALCON512 DILITHIUM2 SPHINCS+-SHA256-128S"

for SCENARIO in $SCENARIOS
do
	mkdir -p $WORKDIRROOT"/"$SCENARIO
	for ALG in $ALGS
	do
		for UDPSIZE in $MAXUDP
		do
			mkdir -p  $WORKDIRROOT"/"$SCENARIO"/"$ALG"_"$UDPSIZE
			cd  $WORKDIRROOT"/"$SCENARIO"/"$ALG"_"$UDPSIZE
			cp $TARDIR"/"$SCENARIO"/X86_64_"$ALG"_"$UDPSIZE".tar" .
			tar -xf $TARDIR"/"$SCENARIO"/X86_64_"$ALG"_"$UDPSIZE".tar"
			for i in {0..1000}
			do
				if [[ -f "run_"$i".log" ]]
				then
					grep 'Query time: ' run_$i.log | cut -d ' ' -f 4 >> scratch.log
				else
					continue
				fi
			done
			st scratch.log > stats.log
		done
	done
done
