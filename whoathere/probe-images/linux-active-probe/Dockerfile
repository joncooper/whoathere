FROM moby/buildkit:buildx-stable-1

COPY whoathere-active-probe /usr/local/bin/whoathere-active-probe
RUN chmod 0555 /usr/local/bin/whoathere-active-probe

ENTRYPOINT ["/usr/local/bin/whoathere-active-probe"]
