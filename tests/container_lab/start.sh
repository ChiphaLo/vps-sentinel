#!/bin/sh
set -eu
ssh-keygen -A >/dev/null 2>&1
cat > /lab/rsyslog.conf <<'EOF'
module(load="imuxsock")
auth,authpriv.* /var/log/auth.log
EOF
rsyslogd -n -i /lab/rsyslog.pid -f /lab/rsyslog.conf &
/usr/sbin/sshd -D -o PasswordAuthentication=yes -o PermitRootLogin=no -o UsePAM=no &
python3 /opt/lab/server.py &
exec sleep infinity
