FROM docker:cli

# Install bash and python3 — crond is already built into Alpine
RUN apk add --no-cache bash python3

# Copy the crontab file into the container
COPY crontab /etc/crontabs/root

# Create directories for reports and metrics
RUN mkdir -p /reports /metrics

# Use busybox crond — works on Mac Docker without setpgid restriction
CMD ["crond", "-f", "-d", "8"]