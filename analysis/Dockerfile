# to use this:
# docker buildx build -o out/ .
# (will copy the rootfs of `output` to out/)

FROM ubuntu:22.04 as build



# Install base utilities
RUN apt-get update \
    && apt-get install -y build-essential git \
    && apt-get install -y wget xxd unzip time \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install miniconda
ENV CONDA_DIR /opt/conda
RUN wget --quiet https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/miniconda.sh && \
    /bin/bash ~/miniconda.sh -b -p /opt/conda

# Put conda in path so we can use conda activate
ENV PATH=$CONDA_DIR/bin:$PATH


WORKDIR /root/analysis
# Setup the conda environment
COPY environment.yml .

ENV PATH=/root/analysis/dep/e9patch/:$PATH
RUN conda env create -f environment.yml

# Set the shell to use conda's fpvm environment
SHELL ["conda", "run", "-n", "fpvm_static_analysis_env", "/bin/bash", "-c"]

COPY src src

COPY workspace /root/workspace
RUN mkdir -p /root/output
RUN /root/analysis/src/run.sh /root/workspace/input 2>&1 > /root/output/analysis.out
RUN cp /root/analysis/src/*_patches.csv /root/output/
# RUN cp /root/analysis/src/*.profile /root/output/
RUN cp /root/analysis/src/*.timing /root/output/

FROM scratch as output
COPY --from=build /root/output .

