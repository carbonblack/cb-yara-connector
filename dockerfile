FROM centos:7
RUN yum -y install rpm-build
RUN yum -y install epel-release
RUN yum -y install python36 python36-devel
RUN yum -y install git
RUN yum -y install make
RUN yum -y install gcc gcc-devel
RUN yum -y install automake libtool make gcc
RUN groupadd -r cb && useradd --no-log-init -r -g cb cb
RUN mkdir /home/cb
RUN chown cb:cb /home/cb
RUN pip3 install virtualenv virtualenvwrapper 
USER cb
WORKDIR /home/cb
RUN mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
RUN virtualenv yaraconnector
RUN source ./yaraconnector/bin/activate
RUN git clone https://github.com/carbonblack/cb-yara-connector
WORKDIR /home/cb/cb-yara-connector
RUN git checkout feature-cb-28268
RUN pip3 install -r requirements.txt --user
RUN pip3 install pyinstaller==3.5.0 --user
ENV PATH $PATH:~/.local/bin
RUN make clean ; make rpm
USER root
#RUN yum install -y /home/cb/rpmbuild/RPMS/x86_64/python-cb-yara-connector.*.rpm
CMD ["/bin/bash","-c"]
