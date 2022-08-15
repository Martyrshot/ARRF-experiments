#! /bin/bash

export NUM_EXPS=$(expr $2 - $1)
#docker compose build --build-arg "SIGN=$(date +%Y%m%d-%H%M%S)"
cd build
mkdir -p dig_logs
./tmux-run-docker-part1.bash
cd ..
cd build
echo "Starting experiments"
if [[ $3 != "JUST_RESULTS" ]]
then
	for i in $(seq $1 $(expr $2 - 1))
	do
		echo $i
		./tmux-run-docker-part2.bash $i
		export FILESIZE=$(wc -c dig_logs/run_$i.log)
		export fails=-1
		while [[ $FILESIZE < 800 ]]
		do
			fails=$(expr $fails + 1)
			if [[ $fails -ge 3 ]]
			then
				echo "Hit max retrys for run $i"
				echo "Hit max retrys for run $i" >> ../failed.log
				break
			fi	
			echo "Error with run $i"
			docker compose down
			echo "Resetting up docker env"
			./tmux-run-docker-part1.bash
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
