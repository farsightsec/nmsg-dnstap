#!/bin/sh

# This test reads dnstap input from a Unix domain socket
# and writes nmsg to a UDP socket.

# This uses fstrm_replay to read existing testing dnstap data and to
# send to the Unix domain socket
# and uses nmsgtool to listen to the UDP socket for the nmsg data
# and writes in presentation format.

TEST=test-unix-domain-to-nmsg-udp-sock-pres

NMSGTOOL=${NMSGTOOL:-nmsgtool}
FSTRM_REPLAY=${FSTRM_REPLAY:-fstrm_replay}
NMSG_DNSTAP=${NMSG_DNSTAP:-${abs_top_builddir}/src/nmsg-dnstap}

# due to filename length limitation use /tmp instead of ${abs_top_builddir}
NMSG_DNSTAP_UNIX_SOCK="/tmp/${TEST}.unix.sock"
NMSGTOOL_UDP_SOCKET="127.0.0.1/9999"
DNSTAP_INPUT=${abs_top_srcdir}/tests/dnstap-input-data

# remove old outputs
rm -f ${abs_top_builddir}/tests/${TEST}*.out

echo start nmsgtool to listen for the nmsg via UDP
$NMSGTOOL -ddd --unbuffered --readsock ${NMSGTOOL_UDP_SOCKET} --writepres ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.pres.out 2>${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.pres.stderr.out &
NMSGTOOL_PID=$!

sleep 0.25
if ! kill -0 $NMSGTOOL_PID 2>/dev/null; then
  echo $NMSGTOOL IS NOT RUNNING
  exit 1
fi

# this uses default content-type

echo start nmsg-dnstap to read from a Unix domain socket and write nmsg to UDP
$NMSG_DNSTAP -ddddd --unbuffered --writesock ${NMSGTOOL_UDP_SOCKET} --unix ${NMSG_DNSTAP_UNIX_SOCK} 2>${abs_top_builddir}/tests/${TEST}-nmsg-dnstap.stderr.out &
NMSG_DNSTAP_PID=$!

# make sure the listener is up
sleep 1

echo send existing testing dnstap data using fstrm_replay to the Unix domain socket
${FSTRM_REPLAY} --unix ${NMSG_DNSTAP_UNIX_SOCK} --read-file ${DNSTAP_INPUT} --type protobuf:dnstap.Dnstap

# make sure the output is saved
sleep 0.25

# stop the processes
kill $NMSG_DNSTAP_PID
sleep 0.25
kill $NMSGTOOL_PID
sleep 0.25

# the timestamps have to be replaced to be ignored
# [2023-08-14 18:42:33.564949603]
sed -e 's,\] \[[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\] \[,] [TIMESTAMP REMOVED] [,' < ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.pres.out > ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.pres.no-timestamps.out

# comparison data has timestamps removed

echo -n "compare nmsg dnstap presentation data: "
cmp -s ${abs_top_srcdir}/tests/nmsgtool.dnstap.pres ${abs_top_builddir}/tests/${TEST}-nmsgtool.dnstap.pres.no-timestamps.out
if [ $? = "0" ]; then
  echo PASS
else
  status=1
  echo FAIL
  cat ${abs_top_builddir}/tests/${TEST}-nmsg-dnstap.stderr.out
fi

exit $status

