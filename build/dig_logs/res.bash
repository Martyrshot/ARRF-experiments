#! /bin/bash
export NUM_EXPS=$(expr $2 - $1)
export SUM=0
export NUMS=""
for i in $(seq $1 $(expr $2 - 1))
do
	echo $i
	NUMS+=$(grep 'Query time: ' run_$i.log | cut -d ' ' -f 4)" "
	#echo $MS
	#SUM=$(expr $MS + $SUM)
done
#echo $(echo "scale = 4; $SUM / $NUM_EXPS" | bc)
echo $NUMS | tr " " "\n" | gnuplot -e 'stats "-"'

