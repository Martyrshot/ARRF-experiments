#! /bin/bash

export NUM_EXPS=$(expr $2 - $1)
cd build
mkdir -p dig_logs
#docker compose build --build-arg "SIGN=$(date +%Y%m%d-%H%M%S)"
# ./tmux-run-docker-part1.bash
if [[ $3 != "JUST_RESULTS" ]]
then
	for i in $(seq $1 $(expr $2 - 1))
	do
		echo $i
		./tmux-run-docker-part2.bash $i
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