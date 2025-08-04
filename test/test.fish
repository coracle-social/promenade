rm -rf /tmp/coord1 /tmp/signer1 /tmp/signer2 /tmp/signer3 /tmp/signer4

nak serve --port 11111 &
set pid_relay $last_pid

go build -o /tmp/coordinator ./coordinator
SECRET_KEY=(nak key generate) DOMAIN=localhost PORT=18686 DB_PATH=/tmp/coord1 /tmp/coordinator &
set pid_coord $last_pid
trap 'kill $pid_relay $pid_coord' SIGINT SIGTERM SIGQUIT EXIT
sleep 2

go build -o /tmp/signer ./signer
set signersk1 1100000000000000000000000000000000000000000000000000000000000001
/tmp/signer --shards-db=/tmp/signer1 --accept-relay=localhost:11111 --sec=$signersk1 &
set pid_signer1 $last_pid
trap 'kill $pid_relay $pid_coord $pid_signer1' SIGINT SIGTERM SIGQUIT EXIT

set signersk2 2200000000000000000000000000000000000000000000000000000000000002
/tmp/signer --shards-db=/tmp/signer2 --accept-relay=localhost:11111 --sec=$signersk2 &
set pid_signer2 $last_pid
trap 'kill $pid_relay $pid_coord $pid_signer1 $pid_signer2' SIGINT SIGTERM SIGQUIT EXIT

set signersk3 3300000000000000000000000000000000000000000000000000000000000003
/tmp/signer --shards-db=/tmp/signer3 --accept-relay=localhost:11111 --sec=$signersk3 &
set pid_signer3 $last_pid
trap 'kill $pid_relay $pid_coord $pid_signer1 $pid_signer2 $pid_signer3' SIGINT SIGTERM SIGQUIT EXIT

set signersk4 4400000000000000000000000000000000000000000000000000000000000004
/tmp/signer --shards-db=/tmp/signer4 --accept-relay=localhost:11111 --sec=$signersk4 &
set pid_signer4 $last_pid
trap 'kill $pid_relay $pid_coord $pid_signer1 $pid_signer2 $pid_signer3 $pid_signer4' SIGINT SIGTERM SIGQUIT EXIT

sleep 8

set usersk1 (nak key generate)
nak event --sec $usersk1 -k 10002 -t r='wss://relay.primal.net' -t r='ws://localhost:11111' relay.primal.net purplepag.es
set bunker1 (go run ./accountcreator create --sec=$usersk1 --threshold 3 --signer=(nak key public $signersk1) --signer=(nak key public $signersk2) --signer=(nak key public $signersk3) --signer=(nak key public $signersk4) --coordinator=localhost:18686)

sleep 4

# set usersk2 (nak key generate)
# nak event --sec $usersk2 -k 10002 -t r='wss://relay.primal.net' -t r='ws://localhost:11111' relay.primal.net purplepag.es
# set bunker2 (go run ./accountcreator create --sec=$usersk2 --threshold 3 --signer=(nak key public $signersk2) --signer=(nak key public $signersk3) --signer=(nak key public $signersk4) --signer=(nak key public $signersk1)  --coordinator=localhost:18686)

echo '
--- actually making the event now
'

sleep 1

set actual (nak event --sec "$bunker1" --ts '2018-05-19 03:37' | jq -r .id)
set expected (nak event --sec $usersk1 --ts '2018-05-19 03:37' | jq -r .id)
echo 'bunker  :' $bunker1
echo 'actual  :' $actual
echo 'expected:' $expected
if [ "$actual" != "$expected" ]
  kill $pid_relay $pid_coord $pid_signer1 $pid_signer2 $pid_signer3 $pid_signer4
  exit 55
end

kill $pid_relay $pid_coord $pid_signer1 $pid_signer2 $pid_signer3 $pid_signer4
