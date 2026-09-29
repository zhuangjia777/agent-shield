FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /etc/ssh \
 && echo 'root:demo123' | chpasswd \
 && printf 'PermitRootLogin yes\nPasswordAuthentication yes\nUsePAM yes\nBanner /etc/issue.net\nPrintMotd no\n' > /etc/ssh/sshd_config.d/ops.conf \
 && printf 'aslab-ops SSH - authorized access only\n' > /etc/issue.net
EXPOSE 22
CMD ["sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
