ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# Python path to the service class from your service directory
ENV SERVICE_PATH=supplyline.supplyline.Supplyline

# Install apt dependencies
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Install python dependencies
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install \
    --no-cache-dir \
    --user \
    --requirement requirements.txt && \
    rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

USER root
RUN chown -R 1000:1000 ./sandlock

USER assemblyline
# Patch version in manifest
ARG version=1.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Install .Net runtime & SDK
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools

RUN curl -L https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh
RUN chmod +x dotnet-install.sh
RUN ./dotnet-install.sh --version 10.0.203 --install-dir $DOTNET_ROOT
RUN rm ./dotnet-install.sh

RUN apt-get update && apt-get install -y build-essential curl

# Switch to assemblyline user
USER assemblyline

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN . $HOME/.cargo/env && pip install --no-cache-dir ./sandlock/python

RUN mkdir -p $HOME/.local/share/supplyshell-libs
RUN mkdir /tmp/supplyshell/

# version environment variable has a meaning to the .net command, so we clear it first.
RUN /bin/bash -c '( \
        set -e; \
        unset version; \
        dotnet publish ./dotnet-dependencies.config \
            -c Release \
            -o $HOME/.local/share/supplyshell-libs \
            --no-self-contained \
            /p:GenerateRuntimeConfigurationFiles=false \
            /p:BaseOutputPath=/tmp/supplyshell/bin/ \
            /p:BaseIntermediateOutputPath=/tmp/supplyshell/obj/ \
            /p:MSBuildProjectExtensionsPath=/tmp/supplyshell/obj/ \
    )'

RUN rm -rf /tmp/supplyshell
