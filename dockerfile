FROM centos:7
RUN yum -y install rpm-build epel-release
RUN yum -y install python36 python36-devel git make gcc gcc-devel automake libtool make
RUN groupadd -r cb && useradd --no-log-init -r -g cb cb
RUN mkdir /home/cb && \
    chown cb:cb /home/cb
RUN pip3 install virtualenv virtualenvwrapper 
USER cb
WORKDIR /home/cb
ENV PATH ~/yaraconnector/bin:$PATH:~/.local/bin
ARG REBUILD_STEP=unknown
RUN REBUILD_STEP=${REBUILD_STEP} mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
RUN virtualenv yaraconnector
COPY --chown=cb ./ /home/cb/cb-yara-connector/
WORKDIR /home/cb/cb-yara-connector
RUN pip3 install -r requirements.txt
RUN pip3 install pyinstaller==3.5.0
RUN make clean ; make rpm
USER root
CMD ["/bin/bash","-c"]
