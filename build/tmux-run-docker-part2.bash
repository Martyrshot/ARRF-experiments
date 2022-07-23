#! /bin/bash
tmux select-pane -t 1
tmux send-keys 'dig test'$1'.goertzen' Enter
sleep 0.5
tmux capture-pane -pS - > dig_logs/run_$1.log
tmux send-keys -R Enter
tmux clear-history
