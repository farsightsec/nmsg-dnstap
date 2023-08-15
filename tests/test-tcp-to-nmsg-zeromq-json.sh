#!/bin/sh

# This test reads dnstap input over TCP
# and writes nmsg to zeromq.

# This uses fstrm_replay to read existing testing dnstap data and to
# send over TCP
# and uses nmsgtool to listen to the zeromq for the nmsg data
# and writes in JSON format.

TEST=test-tcp-to-nmsg-zeromq-json

NMSGTOOL=${NMSGTOOL:-nmsgtool}
FSTRM_REPLAY=${FSTRM_REPLAY:-fstrm_replay}
NMSG_DNSTAP=${NMSG_DNSTAP:-${abs_top_builddir}/src/nmsg-dnstap}

# due to filename length limitation use /tmp instead of ${abs_top_builddir}
NMSG_ZEROMQ_SOCKET="ipc:///tmp/${TEST}.zeromq.sock"
NMSG_DNSTAP_IP=127.0.0.1	# TCP
NMSG_DNSTAP_PORT=9999
DNSTAP_INPUT=${abs_top_srcdir}/tests/dnstap-input-data

# remove old outputs
rm -f ${abs_top_builddir}/tests/${TEST}*.out

echo start nmsgtool to listen for the nmsg via UDP
$NMSGTOOL -ddd --unbuffered --readzsock ${NMSG_ZEROMQ_SOCKET},connect,pushpull --writejson ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.json.out 2>${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.json.stderr.out &
NMSGTOOL_PID=$!

sleep 0.25
if ! kill -0 $NMSGTOOL_PID 2>/dev/null; then
  echo $NMSGTOOL not started
  exit 1
fi

# this sets the content-type to the default value

echo start nmsg-dnstap to read TCP socket and write nmsg via Zeromq
$NMSG_DNSTAP -ddddd --unbuffered --type protobuf:dnstap.Dnstap --writezsock ${NMSG_ZEROMQ_SOCKET},accept,pushpull --tcp ${NMSG_DNSTAP_IP} --port ${NMSG_DNSTAP_PORT} 2>${abs_top_builddir}/tests/${TEST}-nmsg-dnstap.stderr.out &
NMSG_DNSTAP_PID=$!

# make sure the listener is up
sleep 0.25

echo send existing testing dnstap data using fstrm_replay to the TCP socket
${FSTRM_REPLAY} --tcp ${NMSG_DNSTAP_IP} --port ${NMSG_DNSTAP_PORT} --read-file ${DNSTAP_INPUT} --type protobuf:dnstap.Dnstap

# make sure the output is saved
sleep 0.25

# stop the processes
kill $NMSG_DNSTAP_PID
sleep 0.25
kill $NMSGTOOL_PID
sleep 0.25

# the timestamps have to be replaced to be ignored
# [2023-08-14 18:42:33.564949603]
sed -e 's,"time":"[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]","time":"TIMESTAMP REMOVED",' < ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.json.out > ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.json.no-timestamps.out

# comparison data has timestamps removed

echo -n "compare nmsg dnstap json data: "
cmp -s ${abs_top_srcdir}/tests/nmsgtool.dnstap.json ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.json.no-timestamps.out
if [ $? = "0" ]; then
  echo PASS
else
  status=1
  echo FAIL
fi

exit $status

