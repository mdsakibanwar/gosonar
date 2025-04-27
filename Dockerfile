FROM ubuntu:latest

# Set the Current Working Directory inside the container
WORKDIR /home/ubuntu/

RUN apt-get update && apt-get install -y libffi-dev git python3-graph-tool wget build-essential flex bison libgmp-dev libmpfr-dev libmpc-dev texinfo wget zlib1g-dev libisl-dev


# build and install gccgo super expensive operation be cautious
RUN wget https://ftp.gnu.org/gnu/gcc/gcc-10.5.0/gcc-10.5.0.tar.xz
RUN tar -xf gcc-10.5.0.tar.xz
RUN cd gcc-10.5.0; ./contrib/download_prerequisites
RUN mkdir gccgo-build; cd gccgo-build; ../gcc-10.5.0/configure  --prefix=/home/ubuntu/gccgo  --enable-languages=go  --disable-multilib  --enable-checking=release  --enable-lto  --with-system-zlib  --enable-libstdcxx-debug  CFLAGS='-O0 -g3'  CXXFLAGS='-O0 -g3';
RUN cd gccgo-build; make -j $(nproc); make install

# install conda 
RUN wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
RUN bash Miniconda3-latest-Linux-x86_64.sh -b -p /opt/conda

# install go-latest
RUN wget https://go.dev/dl/go1.23.5.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.23.5.linux-amd64.tar.gz

# Copy the repository
COPY . /home/ubuntu/gosonar

# Conda init
ENV PATH="/opt/conda/bin:${PATH}"
RUN conda env create -f /home/ubuntu/gosonar/src/environment.yml
RUN conda init

# Update .bashrc to include Go and GCCGO and conda paths
RUN echo "export PATH=/opt/conda/bin:\$PATH" >> ~/.bashrc
RUN echo "export PATH=/usr/local/go/bin:\$PATH" >> ~/.bashrc
RUN echo "export PATH=/home/ubuntu/gccgo/bin:\$PATH" >> ~/.bashrc
RUN echo "conda activate gosonar" >> ~/.bashrc

# Update intergraph to have label_map and in from_networkx
RUN sed -i '/self.use_labels = True/a\        self.label_map = label_map' /opt/conda/envs/gosonar/lib/python3.12/site-packages/pyintergraph/Graph.py
RUN sed -i '13s/self, nodes, node_labels, node_attributes, edges, edge_attributes, is_directed/self, nodes, node_labels, node_attributes, edges, edge_attributes, is_directed, label_map=None/' /opt/conda/envs/gosonar/lib/python3.12/site-packages/pyintergraph/Graph.py
RUN sed -i '61s/$/, label_map/' /opt/conda/envs/gosonar/lib/python3.12/site-packages/pyintergraph/Graph.py


# Copy the indirect concretization files inside angr
RUN cp /home/ubuntu/gosonar/src/indirect_concretization_mixin.py /opt/conda/envs/gosonar/lib/python3.12/site-packages/angr/storage/memory_mixins/indirect_concretization_mixin.py
RUN sed -i "176a from .indirect_concretization_mixin import IndirectCallConcritizationMixin" /opt/conda/envs/gosonar/lib/python3.12/site-packages/angr/storage/memory_mixins/__init__.py
RUN sed -i "214s/ActionsMixinHigh,/ActionsMixinHigh,\\nIndirectCallConcritizationMixin,/" /opt/conda/envs/gosonar/lib/python3.12/site-packages/angr/storage/memory_mixins/__init__.py
