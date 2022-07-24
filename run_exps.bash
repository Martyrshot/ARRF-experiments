#! /bin/bash

export NUM_EXPS=$(expr $2 - $1)
mkdir -p dig_logs
#docker compose build --build-arg "SIGN=$(date +%Y%m%d-%H%M%S)"
cd build
./tmux-run-docker-part1.bash
cd ..
echo "Setting network conditions..."
./set_network_conditions.bash
cd build
echo "Starting experiments"
if [[ $3 != "JUST_RESULTS" ]]
then
	for i in $(seq $1 $(expr $2 - 1))
	do
		echo $i
		./tmux-run-docker-part2.bash $i
		export FILESIZE=$(wc -c dig_logs/run_$i.log)
		while [[ $FILESIZE < 800 ]]
		do
			echo "Error with run $i"
			docker compose down
			echo "Resetting up docker env"
			./tmux-run-docker-part1.bash
			echo "Setting network conditions..."
			./../set_network_conditions.bash
			echo "Rerunning $i"
			./tmux-run-docker-part2.bash $i
			FILESIZE=$(wc -c dig_logs/run_$i.log)
		done
	done
fi

export SUM=0
for i in $(seq $1 $(expr $2 - 1))
do
	echo $i
	export MS=$(grep 'Query time: ' dig_logs/run_$i.log | cut -d ' ' -f 4)
	#echo $MS
	SUM=$(expr $MS + $SUM)
done
echo $(echo "scale = 4; $SUM / $NUM_EXPS" | bc)
