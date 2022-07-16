#! /bin/bash
tmux new-session -d -s 'docker-bind' -n 'bind' 'docker compose up ns1_root'
sleep 4
tmux split-window -t 'bind' -h 'docker compose up resolver'
sleep 4
tmux split-window -t 'bind' -v 'docker compose up ns1_goertzen host1 client1'
sleep 4
tmux select-pane -t 0
tmux split-window -t 'bind' -v 'docker exec -it build-client1-1 /bin/bash'
sleep 4
tmux select-pane -t 1
tmux a -t 'docker-bind'
