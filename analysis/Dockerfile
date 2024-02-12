# to use this:
# docker buildx build -o out/ .
# (will copy the rootfs of `output` to out/)

FROM ubuntu:22.04 as build



# Install base utilities
RUN apt-get update \
    && apt-get install -y build-essential git \
    && apt-get install -y wget xxd unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install miniconda
ENV CONDA_DIR /opt/conda
RUN wget --quiet https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda.sh && \
    /bin/bash ~/miniconda.sh -b -p /opt/conda

# Put conda in path so we can use conda activate
ENV PATH=$CONDA_DIR/bin:$PATH


WORKDIR /root/analysis
COPY src src
COPY patch patch
COPY environment.yml .

RUN git config --global user.email "you@example.com"
RUN git config --global user.name "Your Name"

# 
RUN mkdir -p dep

# Setup e9patch
RUN git clone https://github.com/GJDuck/e9patch.git dep/e9patch
RUN cd dep/e9patch && ./build.sh

# Setup angr
RUN git clone https://github.com/angr/angr.git dep/angr
RUN git -C dep/angr checkout 25844567d18564095e2e1f1b4f74141f76e8101f

RUN ls -la /root/analysis
RUN git -C dep/angr am --reject --whitespace=fix /root/analysis/patch/angr.patch
RUN cp -r dep/angr/angr src/
RUN conda env create -f environment.yml

# Set the shell to use conda's fpvm environment
SHELL ["conda", "run", "-n", "fpvm_static_analysis_env", "/bin/bash", "-c"]


COPY workspace /root/workspace
RUN /root/analysis/src/run.sh /root/workspace/input
RUN cp /root/analysis/src/a.out /root/workspace/input.patched
RUN cp /root/analysis/src/input*.csv /root/workspace/


FROM scratch as output
COPY --from=build /root/workspace .

