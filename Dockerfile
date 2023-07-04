ARG VAULT_RUNNER_HELPER
FROM $VAULT_RUNNER_HELPER
COPY openvpn-revoke-certs /usr/local/bin/

ENV PATH=$PATH:/usr/local/bin:/root/.tfenv/bin
