#! /bin/bash
tmux has-session -t docker-bind 2> /dev/null > /dev/null
if [[ $? == 0 ]]
then
	tmux kill-session -t docker-bind
fi

tmux new-session -d -s 'docker-bind' -n 'bind' 'docker compose up ns1_root'
sleep 10
tmux split-window -t 'docker-bind:0' -h 'docker compose up resolver'
sleep 10
tmux split-window -t 'docker-bind:0' -v 'docker compose up ns1_goertzen host1 client1'
sleep 10
tmux split-window -t 'docker-bind:0.0' -v 'docker exec -it build-client1-1 /bin/bash'
sleep 10
#tmux select-pane -t docker-bind:0.1
tmux send-keys -t docker-bind:0.1 'dig +tries=1 +timeout=10 @172.20.0.2 test.goertzen' Enter
sleep 15
tmux capture-pane -t docker-bind:0.1 -pS - > setup.log
tmux send-keys -t docker-bind:0.1 -R Enter
tmux clear-history -t docker-bind:0.1
grep -i 'SERVFAIL' setup.log > /dev/null
while [[ $? == 0 ]]
do
	echo "Trying again..."
	tmux send-keys -t docker-bind:0.1 'exit' Enter
	#tmux select-pane -t 0
	tmux send-keys -t docker-bind:0.0 '^c'
	#tmux select-pane -t 1
	tmux send-keys -t docker-bind:0.1 '^c'
	#tmux select-pane -t 2
	tmux send-keys -t docker-bind:0.2 '^c'
	sleep 15
	tmux has-session -t docker-bind 2> /dev/null > /dev/null
	while [[ $? == 0 ]]
	do
		tmux send-keys -t docker-bind:0.0 '^c'
		sleep 15
		tmux has-session -t docker-bind 2> /dev/null > /dev/null
	done
	tmux new-session -d -s 'docker-bind' -n 'bind' 'docker compose up ns1_root'
	sleep 10
	tmux split-window -t 'docker-bind:0' -h 'docker compose up resolver'
	sleep 10
	tmux split-window -t 'docker-bind:0' -v 'docker compose up ns1_goertzen host1 client1'
	sleep 10
	#tmux select-pane -t bind:0
	tmux split-window -t 'docker-bind:0.0' -v 'docker exec -it build-client1-1 /bin/bash'
	sleep 10
	tmux select-pane -t docker-bind:0.1
	tmux send-keys -t docker-bind:0.1 'dig +tries=1 +timeout=15 @172.20.0.2 test.goertzen' Enter
	sleep 20
	tmux capture-pane -t docker-bind:0.1 -pS - > setup.log
	tmux send-keys -t docker-bind:0.1 -R Enter
	tmux clear-history -t docker-bind:0.1
	grep -i 'SERVFAIL' setup.log > /dev/null
done
