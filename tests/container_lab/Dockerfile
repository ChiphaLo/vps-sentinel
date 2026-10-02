ARG RUNTIME_IMAGE=vps-sentinel:lab-runtime
FROM ${RUNTIME_IMAGE}
# These tools are lab fixtures; they are absent from the runtime image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 openssh-server openssh-client sshpass rsyslog iptables iproute2 libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/www/html /root/.ssh /opt/lab /lab \
    && useradd -m -s /bin/sh labuser \
    && echo 'labuser:disposable-lab-password' | chpasswd
COPY server.py /opt/lab/server.py
COPY start.sh /opt/lab/start.sh
ENTRYPOINT ["sh", "/opt/lab/start.sh"]
